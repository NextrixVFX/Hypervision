#pragma once

namespace std
{
	template <typename type, size_t max_size = 1000>
	class c_vector {
	private:
		type m_data[max_size]{};
		size_t m_size{};
		KSPIN_LOCK m_lock{};

	public:
		c_vector() : m_size(0) {
			nt::ke_initialize_spin_lock(&m_lock);
		}

		c_vector(const c_vector&) = delete;
		c_vector& operator=(const c_vector&) = delete;

		bool push_back_batch(const type* values, size_t count) {
			if (!values || count == 0)
				return false;

			KIRQL old_irql;
			nt::ke_acquire_spin_lock(&m_lock, &old_irql);

			if (m_size + count > max_size) {
				nt::ke_release_spin_lock(&m_lock, old_irql);
				return false;
			}

			nt::rtl_copy_memory(&m_data[m_size], values, count * sizeof(type));
			m_size += count;
			nt::ke_release_spin_lock(&m_lock, old_irql);
			return true;
		}

		// scan_pages / cache_pt are not concurrent. Do not RaiseToDpc — a leaked
		// DISPATCH IRQL plus MmCopyMemory or a PFN touch is DRIVER_IRQL_NOT_LESS_OR_EQUAL.
		bool assign_unlocked(const type* values, size_t count) {
			if (!values || count == 0 || count > max_size)
				return false;
			nt::rtl_copy_memory(m_data, values, count * sizeof(type));
			m_size = count;
			return true;
		}

		bool push_back(const type& value) {
			KIRQL old_irql;
			nt::ke_acquire_spin_lock(&m_lock, &old_irql);

			if (m_size >= max_size) {
				nt::ke_release_spin_lock(&m_lock, old_irql);
				return false;
			}

			m_data[m_size++] = value;
			nt::ke_release_spin_lock(&m_lock, old_irql);
			return true;
		}

		bool pop_back() {
			KIRQL old_irql;
			nt::ke_acquire_spin_lock(&m_lock, &old_irql);

			if (m_size == 0) {
				nt::ke_release_spin_lock(&m_lock, old_irql);
				return false;
			}

			--m_size;

			nt::ke_release_spin_lock(&m_lock, old_irql);
			return true;
		}

		void clear() {
			KIRQL old_irql;
			nt::ke_acquire_spin_lock(&m_lock, &old_irql);

			nt::rtl_zero_memory(m_data, sizeof(type) * m_size);
			m_size = 0;

			nt::ke_release_spin_lock(&m_lock, old_irql);
		}

		bool erase(size_t index) {
			KIRQL old_irql;
			nt::ke_acquire_spin_lock(&m_lock, &old_irql);

			if (index >= m_size) {
				nt::ke_release_spin_lock(&m_lock, old_irql);
				return false;
			}

			if (index < m_size - 1) {
				nt::rtl_move_memory(
					&m_data[index],
					&m_data[index + 1],
					(m_size - index - 1) * sizeof(type)
				);
			}

			--m_size;

			nt::ke_release_spin_lock(&m_lock, old_irql);
			return true;
		}

		bool at(size_t index, type& out_value) {
			KIRQL old_irql;
			nt::ke_acquire_spin_lock(&m_lock, &old_irql);

			if (index >= m_size) {
				nt::ke_release_spin_lock(&m_lock, old_irql);
				return false;
			}

			out_value = m_data[index];

			nt::ke_release_spin_lock(&m_lock, old_irql);
			return true;
		}

		type operator[](size_t index) const {
			if (index >= m_size)
				return type{};
			return m_data[index];
		}

		type& operator[](size_t index) {
			return m_data[index];
		}

		type* data() { return m_data; }
		const type* data() const { return m_data; }

		const type* begin() const { return m_data; }
		const type* end() const { return m_data + m_size; }

		bool reserve(size_t new_size) {
			return new_size <= max_size;
		}

		size_t size() const { return m_size; }
		bool empty() const { return m_size == 0; }
		bool full() const { return m_size >= max_size; }
		size_t capacity() const { return max_size; }
	};
}

namespace mm
{
	class c_paging
	{
		mmpfn_t* m_pfn_database{};
		std::uint16_t m_cached_pml4e{};
		std::uint16_t m_cached_pdpte{};
		std::uint16_t m_cached_pde{};

	public:
		std::c_vector< pml4e, 512 > m_pml4_table{};
		std::c_vector< pdpte, 512 > m_pdpt_table{};
		std::c_vector< pde, 512 > m_pd_table{};
		std::c_vector< pte, 512 > m_pt_table{};
		cr3 m_dtb{};
		pml4e m_pml4_scratch[512]{};
		std::uint8_t m_copy_scratch[page_4kb_size]{};

		void cleanup() {
			m_pml4_table.clear();
			m_pdpt_table.clear();
			m_pd_table.clear();
			m_pt_table.clear();

			m_cached_pml4e = 0;
			m_cached_pdpte = 0;
			m_cached_pde = 0;
			m_dtb.flags = 0;
		}

		bool setup()
		{
			if (!m_pml4_table.empty())
				return false;

			m_pfn_database = nt::get_mm_pfn_database();
			if (!m_pfn_database)
				return false;

			return true;
		}

		std::uint64_t translate(std::uint64_t virtual_address, std::uint32_t* out_page_size = nullptr)
		{
			if (nt::ke_get_current_irql() > PASSIVE_LEVEL)
				return 0;

			if (!m_dtb.flags || !m_pml4_table.data())
				return 0;

			// Canonical address check: bits 63:47 must all be 0 or all be 1
			const std::uint64_t sign_bits = virtual_address >> 47;
			if (sign_bits != 0 && sign_bits != 0x1FFFFull)
				return 0;

			// Only translate user-mode addresses
			if (virtual_address >= 0xFFFF800000000000ull)
				return 0;

			const virt_addr_t va{ virtual_address };

			// ── PML4 ────────────────────────────────────────────────────────────────
			if (va.pml4e_index >= 512)
				return 0;

			const pml4e& pml4_entry = m_pml4_table[va.pml4e_index];
			if (!pml4_entry.hard.present)
				return 0;

			const std::uint64_t pdpt_pa = pml4_entry.hard.pfn << page_shift;

			// ── PDPT ────────────────────────────────────────────────────────────────
			pdpte pdpt_entry{};
			if (phys::read_direct(
				pdpt_pa + va.pdpte_index * sizeof(pdpte),
				&pdpt_entry, sizeof(pdpte)) != nt_status_t::success)
				return 0;

			if (!pdpt_entry.hard.present)
				return 0;

			// 1GB page: bits 29:0 are the page offset
			if (pdpt_entry.hard.page_size)
			{
				// For 1GB pages the PFN field encodes bits 47:30,
				// so mask off the low 18 bits of pfn that are part of the offset
				const std::uint64_t base = (pdpt_entry.hard.pfn & ~0x3FFFFull) << page_shift;
				const std::uint64_t offset = virtual_address & page_1gb_mask;        // 0x3FFFFFFF
				if (out_page_size) *out_page_size = page_1gb_size;
				return base + offset;
			}

			const std::uint64_t pd_pa = pdpt_entry.hard.pfn << page_shift;

			// ── PD ──────────────────────────────────────────────────────────────────
			pde pd_entry{};
			if (phys::read_direct(
				pd_pa + va.pde_index * sizeof(pde),
				&pd_entry, sizeof(pde)) != nt_status_t::success)
				return 0;

			if (!pd_entry.hard.present)
				return 0;

			// 2MB page: bits 20:0 are the page offset
			if (pd_entry.hard.page_size)
			{
				// For 2MB pages the PFN field encodes bits 47:21,
				// so mask off the low 9 bits of pfn that overlap the offset
				const std::uint64_t base = (pd_entry.hard.pfn & ~0x1FFull) << page_shift;
				const std::uint64_t offset = virtual_address & page_2mb_mask;        // 0x1FFFFF
				if (out_page_size) *out_page_size = page_2mb_size;
				return base + offset;
			}

			const std::uint64_t pt_pa = pd_entry.hard.pfn << page_shift;

			// ── PT ──────────────────────────────────────────────────────────────────
			pte pt_entry{};
			if (phys::read_direct(
				pt_pa + va.pte_index * sizeof(pte),
				&pt_entry, sizeof(pte)) != nt_status_t::success)
				return 0;

			if (!pt_entry.hard.present)
				return 0;

			const std::uint64_t base = pt_entry.hard.pfn << page_shift;
			const std::uint64_t offset = virtual_address & page_4kb_mask;            // 0xFFF
			if (out_page_size) *out_page_size = page_4kb_size;
			return base + offset;
		}

		bool commit_pml4(std::uint64_t physical_address)
		{
			for (std::uint16_t i = 0; i < 512; i++)
			{
				if (phys::read_direct(
					physical_address + i * sizeof(pml4e),
					&m_pml4_scratch[i],
					sizeof(pml4e)) != nt_status_t::success)
					return false;
			}

			return m_pml4_table.assign_unlocked(m_pml4_scratch, 512);
		}

		// 8-byte MmCopyMemory only. A 4K copy (WNF local or m_pml4_scratch) overruns
		// the unused slack above the thread's real frames on the VMMCALL stack (0xF7).
		__declspec(noinline) bool cache_pt(std::uint64_t physical_address, std::uint64_t base_address, std::uint16_t signature = 0, bool verbose = false)
		{
			if (nt::ke_get_current_irql() > APC_LEVEL)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail irql %u", nt::ke_get_current_irql());
				return false;
			}

			virt_addr_t va{ base_address };

			pml4e pml4_entry{};
			if (phys::read_direct(
				physical_address + va.pml4e_index * sizeof(pml4e),
				&pml4_entry, sizeof(pml4e)) != nt_status_t::success)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pml4_read 0x%llx", physical_address);
				return false;
			}
			if (!pml4_entry.hard.present)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pml4_present idx=%u val=0x%llx",
						va.pml4e_index, pml4_entry.value);
				return false;
			}

			pdpte pdpt_entry{};
			const std::uint64_t pdpt_pa = (pml4_entry.hard.pfn << page_shift) + (va.pdpte_index * sizeof(pdpte));
			if (phys::read_direct(pdpt_pa, &pdpt_entry, sizeof(pdpt_entry)) != nt_status_t::success)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pdpt_read 0x%llx", pdpt_pa);
				return false;
			}
			if (!pdpt_entry.hard.present)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pdpt_present 0x%llx", pdpt_entry.value);
				return false;
			}
			if (pdpt_entry.hard.page_size)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pdpt_1g 0x%llx", pdpt_entry.value);
				return false;
			}

			pde pd_entry{};
			const std::uint64_t pd_pa = (pdpt_entry.hard.pfn << page_shift) + (va.pde_index * sizeof(pde));
			if (phys::read_direct(pd_pa, &pd_entry, sizeof(pd_entry)) != nt_status_t::success)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pd_read 0x%llx", pd_pa);
				return false;
			}
			if (!pd_entry.hard.present)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pd_present 0x%llx", pd_entry.value);
				return false;
			}

			if (pd_entry.hard.page_size)
			{
				if (signature)
				{
					const std::uint64_t large_pa = (pd_entry.hard.pfn << page_shift) + (base_address & page_2mb_mask);
					std::uint16_t sig{};
					if (phys::read_direct(large_pa, &sig, sizeof(sig)) != nt_status_t::success)
					{
						if (verbose)
							nt::dbg_print("[cache_pt] fail mz_2m_read 0x%llx", large_pa);
						return false;
					}
					if (sig != signature)
					{
						if (verbose)
							nt::dbg_print("[cache_pt] fail mz_2m got=0x%x", sig);
						return false;
					}
				}

				if (!commit_pml4(physical_address))
				{
					if (verbose)
						nt::dbg_print("[cache_pt] fail commit");
					return false;
				}

				m_cached_pml4e = va.pml4e_index;
				m_cached_pdpte = va.pdpte_index;
				m_cached_pde = va.pde_index;
				return true;
			}

			pte pt_entry{};
			const std::uint64_t pt_pa = (pd_entry.hard.pfn << page_shift) + (va.pte_index * sizeof(pte));
			if (phys::read_direct(pt_pa, &pt_entry, sizeof(pt_entry)) != nt_status_t::success)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pt_read 0x%llx", pt_pa);
				return false;
			}
			if (!pt_entry.hard.present)
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail pt_present 0x%llx", pt_entry.value);
				return false;
			}

			if (signature)
			{
				const std::uint64_t final_pa = (pt_entry.hard.pfn << page_shift) + (base_address & page_4kb_mask);
				std::uint16_t sig{};
				if (phys::read_direct(final_pa, &sig, sizeof(sig)) != nt_status_t::success)
				{
					if (verbose)
						nt::dbg_print("[cache_pt] fail mz_read 0x%llx", final_pa);
					return false;
				}
				if (sig != signature)
				{
					if (verbose)
						nt::dbg_print("[cache_pt] fail mz got=0x%x", sig);
					return false;
				}
			}

			if (!commit_pml4(physical_address))
			{
				if (verbose)
					nt::dbg_print("[cache_pt] fail commit");
				return false;
			}

			m_cached_pml4e = va.pml4e_index;
			m_cached_pdpte = va.pdpte_index;
			m_cached_pde = va.pde_index;
			return true;
		}

		__declspec(noinline) bool scan_pages(std::uint64_t base_address, std::uint16_t signature = 0)
		{
			if (!base_address)
				return false;

			nt::dbg_print("[scan_pages] begin base=0x%llx", base_address);

			const auto ranges = nt::mm_get_physical_memory_ranges();
			if (!ranges)
				return false;

			for (auto i = 0; ; i++) {
				auto& memory_range = ranges[i];

				if (!memory_range.BaseAddress.QuadPart &&
					!memory_range.NumberOfBytes.QuadPart)
					break;

				std::uint64_t current_pa = static_cast<std::uint64_t>(memory_range.BaseAddress.QuadPart);
				const std::uint64_t byte_count = static_cast<std::uint64_t>(memory_range.NumberOfBytes.QuadPart);

				nt::dbg_print("[scan_pages] range %d: base_pa=0x%llx bytes=0x%llx",
					i, current_pa, byte_count);

				for (std::uint64_t offset = 0;
					offset < byte_count;
					offset += page_4kb_size, current_pa += page_4kb_size)
				{
					cr3 current_dtb{};
					current_dtb.pfn = current_pa >> page_shift;
					if (!current_dtb.flags)
						continue;

					if (cache_pt(current_pa, base_address, signature))
					{
						m_dtb = current_dtb;
						nt::dbg_print("[scan_pages] found DTB: 0x%llx at PA=0x%llx",
							m_dtb.flags, current_pa);
						nt::free_pool(ranges);
						return true;
					}
				}
			}

			nt::free_pool(ranges);
			return false;
		}

		std::uintptr_t get_dtb() const
		{
			return m_dtb.flags;
		}
	};

	c_paging g_paging;
}

namespace mm::phys
{
	nt_status_t km_safe_read(
		std::uint64_t virtual_address,
		void* out,
		std::size_t size
	)
	{
		if (!virtual_address || !out || !size)
			return nt_status_t::invalid_parameter;

		std::uint8_t* dst = static_cast<std::uint8_t*>(out);
		std::size_t remaining = size;
		std::uint64_t va = virtual_address;

		while (remaining)
		{
			std::uint64_t pa = g_paging.translate(va);
			if (!pa)
				return nt_status_t::unsuccessful;

			// Clamp the read to the end of the current physical page
			std::size_t page_offset = pa & page_4kb_mask;
			std::size_t chunk = min(remaining, page_4kb_size - page_offset);

			auto status = mm::phys::read_direct(pa, dst, chunk);
			if (status != nt_status_t::success)
				return status;

			va += chunk;
			dst += chunk;
			remaining -= chunk;
		}

		return nt_status_t::success;
	}
}
