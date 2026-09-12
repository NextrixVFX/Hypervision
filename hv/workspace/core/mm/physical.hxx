#pragma once

namespace mm::phys
{
	inline constexpr std::uint64_t pte_pfn_mask = 0x000FFFFFFFFFF000ull;

	inline void* g_window{};
	inline volatile std::uint64_t* g_pte{};
	inline std::uint64_t g_pte_original{};
	inline KSPIN_LOCK g_lock{};
	inline volatile LONG g_busy{};
	inline PMDL g_window_mdl{};

	// Snapshot of MmGetPhysicalMemoryRanges as byte PA + byte length.
	// WNF treats those fields as PFN/page-count; range 1 then starts at
	// BaseAddress<<12 (0x1000000000 here) and the first window remap bugchecks.
	inline constexpr std::uint32_t ram_span_max = 64;
	struct ram_span { std::uint64_t base; std::uint64_t end; };
	inline ram_span g_ram[ram_span_max]{};
	inline std::uint32_t g_ram_count{};

	inline bool pa_in_ram(std::uint64_t physical_addr, std::size_t size)
	{
		if (!physical_addr || !size)
			return false;
		if (!g_ram_count)
			return true;

		const std::uint64_t last = physical_addr + (size - 1);
		if (last < physical_addr)
			return false;

		for (std::uint32_t i = 0; i < g_ram_count; ++i)
		{
			if (physical_addr >= g_ram[i].base && last < g_ram[i].end)
				return true;
		}
		return false;
	}

	inline void record_ram_ranges()
	{
		g_ram_count = 0;
		const auto ranges = nt::mm_get_physical_memory_ranges();
		if (!ranges)
			return;

		for (std::uint32_t i = 0; g_ram_count < ram_span_max; ++i)
		{
			if (!ranges[i].BaseAddress.QuadPart && !ranges[i].NumberOfBytes.QuadPart)
				break;

			const std::uint64_t base = static_cast<std::uint64_t>(ranges[i].BaseAddress.QuadPart);
			const std::uint64_t bytes = static_cast<std::uint64_t>(ranges[i].NumberOfBytes.QuadPart);
			if (!bytes)
				continue;

			g_ram[g_ram_count].base = base;
			g_ram[g_ram_count].end = base + bytes;
			++g_ram_count;
		}

		nt::free_pool(ranges);
	}

	inline nt_status_t read_direct(std::uint64_t physical_addr, void* buffer, std::size_t size, size_t* bytes = nullptr)
	{
		if (nt::ke_get_current_irql() > APC_LEVEL)
			return nt_status_t::invalid_device_state;

		MM_COPY_ADDRESS src{};
		src.PhysicalAddress.QuadPart = static_cast<LONGLONG>(physical_addr);

		size_t transferred = 0;
		return static_cast<nt_status_t>(nt::mm_copy_memory(
			buffer,
			src,
			size,
			copy_physical,
			bytes ? bytes : &transferred));
	}

	inline void clear_tf()
	{
		__writeeflags(__readeflags() & ~0x100ull);
	}

	inline std::uint64_t window_pte(std::uint64_t page_pa)
	{
		return (g_pte_original & ~pte_pfn_mask) | (page_pa & pte_pfn_mask) | 1ull;
	}

	__declspec(noinline) inline void remap_window(std::uint64_t page_pa)
	{
		clear_tf();
		*g_pte = window_pte(page_pa);
		__invlpg(g_window);
	}

	__declspec(noinline) inline void restore_window()
	{
		*g_pte = g_pte_original;
		__invlpg(g_window);
		clear_tf();
	}

	inline void copy_from_window(void* dst, std::size_t offset, std::size_t chunk)
	{
		auto* const src = static_cast<std::uint8_t*>(g_window) + offset;
		auto* const out = static_cast<std::uint8_t*>(dst);
		if (chunk == sizeof(std::uint64_t) && !(offset & 7))
			*reinterpret_cast<std::uint64_t*>(out) = *reinterpret_cast<volatile std::uint64_t*>(src);
		else if (chunk == sizeof(std::uint16_t) && !(offset & 1))
			*reinterpret_cast<std::uint16_t*>(out) = *reinterpret_cast<volatile std::uint16_t*>(src);
		else
			crt::memcpy(out, src, chunk);
	}

	inline void lock_window()
	{
		while (InterlockedCompareExchange(&g_busy, 1, 0) != 0)
			_mm_pause();
	}

	inline void unlock_window()
	{
		InterlockedExchange(&g_busy, 0);
	}

	__declspec(noinline) inline nt_status_t read_window(std::uint64_t physical_addr, void* buffer, std::size_t size)
	{
		if (!physical_addr || !buffer || !size || !g_window || !g_pte)
			return nt_status_t::unsuccessful;

		auto* dst = static_cast<std::uint8_t*>(buffer);
		std::size_t remaining = size;

		while (remaining)
		{
			const std::uint64_t offset = physical_addr & page_4kb_mask;
			const std::size_t chunk = min(remaining, page_4kb_size - offset);
			const std::uint64_t page_pa = physical_addr & ~page_4kb_mask;
			if (!pa_in_ram(page_pa, page_4kb_size))
				return nt_status_t::unsuccessful;

			lock_window();
			remap_window(page_pa);
			copy_from_window(dst, offset, chunk);
			restore_window();
			unlock_window();

			physical_addr += chunk;
			dst += chunk;
			remaining -= chunk;
		}

		return nt_status_t::success;
	}

	// Proven path: 8-byte MmCopyMemory into driver BSS. A 4K copy on the
	// VMMCALL stack is 0xF7. Loop so a struct-sized read stays on that path.
	__declspec(noinline) inline nt_status_t read_physical(std::uint64_t physical_addr, void* buffer, std::size_t size)
	{
		if (!physical_addr || !buffer || !size)
			return nt_status_t::invalid_parameter;

		auto* dst = static_cast<std::uint8_t*>(buffer);
		while (size)
		{
			const std::size_t chunk = min(size, sizeof(std::uint64_t));
			const auto status = read_direct(physical_addr, dst, chunk);
			if (status != nt_status_t::success)
				return status;
			physical_addr += chunk;
			dst += chunk;
			size -= chunk;
		}
		return nt_status_t::success;
	}

	inline std::uint64_t va_to_pa(std::uint64_t cr3, std::uint64_t virtual_address)
	{
		if (!cr3)
			return 0;

		const std::uint64_t sign_bits = virtual_address >> 47;
		if (sign_bits != 0 && sign_bits != 0x1FFFFull)
			return 0;

		const virt_addr_t va{ virtual_address };
		const std::uint64_t pml4_pa = cr3 & ~page_4kb_mask;

		pml4e pml4_entry{};
		if (read_direct(pml4_pa + va.pml4e_index * sizeof(pml4e),
			&pml4_entry, sizeof(pml4e)) != nt_status_t::success)
			return 0;
		if (!pml4_entry.hard.present)
			return 0;

		pdpte pdpt_entry{};
		if (read_direct((pml4_entry.hard.pfn << page_shift) + va.pdpte_index * sizeof(pdpte),
			&pdpt_entry, sizeof(pdpte)) != nt_status_t::success)
			return 0;
		if (!pdpt_entry.hard.present)
			return 0;

		if (pdpt_entry.hard.page_size)
			return ((pdpt_entry.hard.pfn & ~0x3FFFFull) << page_shift) + (virtual_address & page_1gb_mask);

		pde pd_entry{};
		if (read_direct((pdpt_entry.hard.pfn << page_shift) + va.pde_index * sizeof(pde),
			&pd_entry, sizeof(pde)) != nt_status_t::success)
			return 0;
		if (!pd_entry.hard.present)
			return 0;

		if (pd_entry.hard.page_size)
			return ((pd_entry.hard.pfn & ~0x1FFull) << page_shift) + (virtual_address & page_2mb_mask);

		pte pt_entry{};
		if (read_direct((pd_entry.hard.pfn << page_shift) + va.pte_index * sizeof(pte),
			&pt_entry, sizeof(pte)) != nt_status_t::success)
			return 0;
		if (!pt_entry.hard.present)
			return 0;

		return (pt_entry.hard.pfn << page_shift) + (virtual_address & page_4kb_mask);
	}

	inline void copy_to_window(const void* src, std::size_t offset, std::size_t chunk)
	{
		auto* const dst = static_cast<std::uint8_t*>(g_window) + offset;
		auto* const in = static_cast<const std::uint8_t*>(src);
		if (chunk == sizeof(std::uint64_t) && !(offset & 7))
			*reinterpret_cast<volatile std::uint64_t*>(dst) = *reinterpret_cast<const std::uint64_t*>(in);
		else if (chunk == sizeof(std::uint32_t) && !(offset & 3))
			*reinterpret_cast<volatile std::uint32_t*>(dst) = *reinterpret_cast<const std::uint32_t*>(in);
		else if (chunk == sizeof(std::uint16_t) && !(offset & 1))
			*reinterpret_cast<volatile std::uint16_t*>(dst) = *reinterpret_cast<const std::uint16_t*>(in);
		else
			crt::memcpy(dst, in, chunk);
	}

	inline std::uint16_t find_self_map()
	{
		const std::uint64_t cr3_pa = __readcr3() & ~page_4kb_mask;
		const std::uint64_t cr3_pfn = cr3_pa >> page_shift;
		pml4e e{};
		constexpr std::uint16_t guesses[] = { 0x1ED, 0x1EE, 0x1F0, 0x1F8, 0x1FF };
		for (auto self : guesses)
		{
			if (read_direct(cr3_pa + self * sizeof(pml4e), &e, sizeof(e)) != nt_status_t::success)
				continue;
			if (e.hard.present && e.hard.pfn == cr3_pfn)
				return self;
		}
		for (std::uint16_t i = 256; i < 512; i++)
		{
			if (read_direct(cr3_pa + i * sizeof(pml4e), &e, sizeof(e)) != nt_status_t::success)
				continue;
			if (e.hard.present && e.hard.pfn == cr3_pfn)
				return i;
		}
		return 0;
	}

	inline volatile std::uint64_t* locate_pte(void* va)
	{
		if (!va)
			return nullptr;

		const virt_addr_t v{ reinterpret_cast<std::uintptr_t>(va) };
		const std::uint64_t cr3_pa = __readcr3() & ~page_4kb_mask;
		const std::uint64_t cr3_pfn = cr3_pa >> page_shift;

		const std::uint16_t self = find_self_map();
		if (!self)
		{
			hv_log("locate_pte: no self-map cr3=%llx pfn=%llx", cr3_pa, cr3_pfn);
			return nullptr;
		}

		pml4e pml4_entry{};
		if (read_direct(cr3_pa + v.pml4e_index * sizeof(pml4e), &pml4_entry, sizeof(pml4_entry)) != nt_status_t::success)
			return nullptr;
		if (!pml4_entry.hard.present)
			return nullptr;

		pdpte pdpt_entry{};
		if (read_direct((pml4_entry.hard.pfn << page_shift) + v.pdpte_index * sizeof(pdpte),
			&pdpt_entry, sizeof(pdpte)) != nt_status_t::success)
			return nullptr;
		if (!pdpt_entry.hard.present)
			return nullptr;
		if (pdpt_entry.hard.page_size)
		{
			hv_log("locate_pte: 1GB map va=%p", va);
			return nullptr;
		}

		pde pd_entry{};
		if (read_direct((pdpt_entry.hard.pfn << page_shift) + v.pde_index * sizeof(pde),
			&pd_entry, sizeof(pde)) != nt_status_t::success)
			return nullptr;
		if (!pd_entry.hard.present)
			return nullptr;
		if (pd_entry.hard.page_size)
		{
			hv_log("locate_pte: 2MB map va=%p self=%x", va, self);
			return nullptr;
		}

		pte pt_entry{};
		if (read_direct((pd_entry.hard.pfn << page_shift) + v.pte_index * sizeof(pte),
			&pt_entry, sizeof(pte)) != nt_status_t::success)
			return nullptr;
		if (!pt_entry.hard.present)
			return nullptr;

		virt_addr_t pte_v{};
		pte_v.offset = static_cast<std::uint64_t>(v.pte_index) * sizeof(pte);
		pte_v.pte_index = v.pde_index;
		pte_v.pde_index = v.pdpte_index;
		pte_v.pdpte_index = v.pml4e_index;
		pte_v.pml4e_index = self;
		pte_v.reserved = 0xFFFF;

		auto* const pte_ptr = reinterpret_cast<volatile std::uint64_t*>(pte_v.value);
		if (!nt::mm_is_address_valid(reinterpret_cast<void*>(pte_v.value)))
		{
			hv_log("locate_pte: pte va invalid %p self=%x", reinterpret_cast<void*>(pte_v.value), self);
			return nullptr;
		}

		if ((*pte_ptr & pte_pfn_mask) != (pt_entry.value & pte_pfn_mask) || (*pte_ptr & 1) == 0)
		{
			hv_log("locate_pte: pte mismatch self=%x", self);
			return nullptr;
		}

		hv_log("locate_pte: ok self=%x pte=%p", self, pte_ptr);
		return pte_ptr;
	}

	inline bool bind_window(void* va)
	{
		g_pte = locate_pte(va);
		if (!g_pte)
			return false;
		g_window = va;
		g_pte_original = *g_pte;
		if ((g_pte_original & 1) == 0)
		{
			hv_log("window PTE not present");
			g_pte = nullptr;
			g_window = nullptr;
			return false;
		}
		hv_log("phys window va=%p pte=%p orig=%llx", g_window, g_pte, g_pte_original);
		return true;
	}

	inline bool setup()
	{
		nt::ke_initialize_spin_lock(&g_lock);
		g_busy = 0;
		g_window = nullptr;
		g_pte = nullptr;
		g_pte_original = 0;
		g_window_mdl = nullptr;
		record_ram_ranges();
		hv_log("ram spans=%u", g_ram_count);

		if (void* const va = nt::alloc_contig(page_4kb_size))
		{
			if (bind_window(va))
				return true;
			nt::free_contig(va);
		}

		if (void* const va = nt::ex_allocate_pool(page_4kb_size))
		{
			if (bind_window(va))
				return true;
			nt::free_pool(va);
		}

		PHYSICAL_ADDRESS low{};
		PHYSICAL_ADDRESS high{};
		PHYSICAL_ADDRESS skip{};
		high.QuadPart = ~0ULL;
		g_window_mdl = nt::mm_allocate_pages_for_mdl(low, high, skip, page_4kb_size);
		if (g_window_mdl)
		{
			void* const va = nt::mm_map_locked_pages_specify_cache(
				g_window_mdl, KernelMode, MmCached, nullptr, FALSE, 16);
			if (va && bind_window(va))
				return true;
			if (va)
				nt::mm_unmap_locked_pages(va, g_window_mdl);
			nt::mm_free_pages_from_mdl(g_window_mdl);
			nt::free_pool(g_window_mdl);
			g_window_mdl = nullptr;
		}

		hv_log("phys window unavailable");
		return true;
	}

	__declspec(noinline) inline nt_status_t write_direct(std::uint64_t physical_addr, PVOID buffer, size_t size, size_t* bytes = nullptr)
	{
		if (!physical_addr || !buffer || !size)
			return nt_status_t::unsuccessful;

		auto* src = static_cast<std::uint8_t*>(buffer);
		std::size_t remaining = size;

		while (remaining)
		{
			const std::uint64_t offset = physical_addr & page_4kb_mask;
			const std::size_t chunk = min(remaining, page_4kb_size - offset);
			const std::uint64_t page_pa = physical_addr & ~page_4kb_mask;
			if (!pa_in_ram(page_pa, page_4kb_size))
				return nt_status_t::unsuccessful;

			if (g_window && g_pte)
			{
				lock_window();
				remap_window(page_pa);
				copy_to_window(src, offset, chunk);
				restore_window();
				unlock_window();
			}
			else
			{
				PHYSICAL_ADDRESS mapped{};
				mapped.QuadPart = static_cast<LONGLONG>(page_pa);
				void* const va = nt::mm_map_io_space_ex(mapped, page_4kb_size, PAGE_READWRITE);
				if (!va)
					return nt_status_t::unsuccessful;
				crt::memcpy(static_cast<std::uint8_t*>(va) + offset, src, chunk);
				nt::mm_unmap_io_space(va, page_4kb_size);
			}

			physical_addr += chunk;
			src += chunk;
			remaining -= chunk;
		}

		if (bytes)
			*bytes = size;
		return nt_status_t::success;
	}

	inline nt_status_t read_direct_safe(std::uint64_t physical_addr, void* buffer, std::size_t size)
	{
		if (!physical_addr || !buffer || !size)
			return nt_status_t::invalid_parameter;
		if (nt::ke_get_current_irql() > APC_LEVEL)
			return nt_status_t::invalid_device_state;

		MM_COPY_ADDRESS src{};
		src.PhysicalAddress.QuadPart = static_cast<LONGLONG>(physical_addr);

		std::size_t bytes_copied = 0;
		const auto status = nt::mm_copy_memory(buffer, src, size, copy_physical, &bytes_copied);
		if (status != nt_status_t::success || bytes_copied != size)
		{
			nt::dbg_print("[read_direct_safe] failed: status=0x%llx copied=%zu expected=%zu",
				static_cast<std::uint64_t>(status), bytes_copied, size);
			return nt_status_t::unsuccessful;
		}

		return nt_status_t::success;
	}
}
