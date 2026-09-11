#pragma once

namespace npt
{
	class c_npt
	{
		void* m_pages[npt_max_pages]{};
		std::uint32_t m_page_count{};
		std::uint64_t* m_pml4{};

	public:
		KSPIN_LOCK m_lock{};

		std::uint64_t* alloc_table()
		{
			if (m_page_count >= npt_max_pages)
				return nullptr;

			void* const page = nt::alloc_contig(page_4kb_size);
			if (!page)
				return nullptr;

			m_pages[m_page_count++] = page;
			return static_cast<std::uint64_t*>(page);
		}

		void* va_from_pa(std::uint64_t pa)
		{
			PHYSICAL_ADDRESS phys{};
			// APM Vol. 2 (24593) §5.4.1: physical-page numbers sit in bits 51:12;
			// NX is bit 63 of the same qword, so it must be stripped before treating
			// the entry as a host physical address.
			phys.QuadPart = static_cast<LONGLONG>(pa & ~page_4kb_mask & ~amd::npt_nx);
			return nt::mm_get_virtual_for_physical(phys);
		}

		bool walk_map(std::uint64_t gpa, std::uint64_t hpa, std::uint64_t flags, bool large)
		{
			if (!m_pml4)
				return false;

			// APM Vol. 2 (24593) §5.3 long-mode 4-level translation of a 4K page:
			// "Bits 47:39 index into the 512-entry page-map level-4 table."
			// "Bits 38:30 index into the 512-entry page-directory pointer table."
			// "Bits 29:21 index into the 512-entry page-directory table."
			// "Bits 20:12 index into the 512-entry page table."
			const std::uint32_t pml4i = (gpa >> 39) & 0x1FF;
			const std::uint32_t pdpti = (gpa >> 30) & 0x1FF;
			const std::uint32_t pdi = (gpa >> 21) & 0x1FF;
			const std::uint32_t pti = (gpa >> 12) & 0x1FF;

			if ((m_pml4[pml4i] & amd::npt_present) == 0)
			{
				std::uint64_t* const pdpt = alloc_table();
				if (!pdpt)
					return false;
				m_pml4[pml4i] = nt::pa(pdpt) | amd::npt_rwx;
			}

			auto* const pdpt = static_cast<std::uint64_t*>(va_from_pa(m_pml4[pml4i]));
			if ((pdpt[pdpti] & amd::npt_present) == 0)
			{
				std::uint64_t* const pd = alloc_table();
				if (!pd)
					return false;
				pdpt[pdpti] = nt::pa(pd) | amd::npt_rwx;
			}
			else if (pdpt[pdpti] & amd::npt_large)
			{
				return false;
			}

			auto* const pd = static_cast<std::uint64_t*>(va_from_pa(pdpt[pdpti]));
			if (large)
			{
				// APM Vol. 2 (24593) §5.3.4: with PDE.PS=1, "Bits 20:0 provide the byte
				// offset into the physical page" so the host address must be 2-Mbyte
				// aligned and PS (bit 7) set in the PDE.
				pd[pdi] = (hpa & ~page_2mb_mask) | flags | amd::npt_large;
				return true;
			}

			if ((pd[pdi] & amd::npt_present) && (pd[pdi] & amd::npt_large))
				return false;

			if ((pd[pdi] & amd::npt_present) == 0)
			{
				std::uint64_t* const pt = alloc_table();
				if (!pt)
					return false;
				pd[pdi] = nt::pa(pt) | amd::npt_rwx;
			}

			auto* const pt = static_cast<std::uint64_t*>(va_from_pa(pd[pdi]));
			pt[pti] = (hpa & ~page_4kb_mask) | flags;
			return true;
		}

		bool map_2mb(std::uint64_t gpa, std::uint64_t hpa, std::uint64_t flags)
		{
			return walk_map(gpa, hpa, flags, true);
		}

		bool map_4k(std::uint64_t gpa, std::uint64_t hpa, std::uint64_t flags)
		{
			return walk_map(gpa, hpa, flags, false);
		}

		bool split_2mb(std::uint64_t gpa)
		{
			if (!m_pml4)
				return false;

			const std::uint32_t pml4i = (gpa >> 39) & 0x1FF;
			const std::uint32_t pdpti = (gpa >> 30) & 0x1FF;
			const std::uint32_t pdi = (gpa >> 21) & 0x1FF;

			if ((m_pml4[pml4i] & amd::npt_present) == 0)
				return map_4k(gpa, gpa, amd::npt_rwx);

			auto* const pdpt = static_cast<std::uint64_t*>(va_from_pa(m_pml4[pml4i]));
			if ((pdpt[pdpti] & amd::npt_present) == 0)
				return map_4k(gpa, gpa, amd::npt_rwx);

			auto* const pd = static_cast<std::uint64_t*>(va_from_pa(pdpt[pdpti]));
			if ((pd[pdi] & amd::npt_present) == 0)
				return map_4k(gpa, gpa, amd::npt_rwx);

			if ((pd[pdi] & amd::npt_large) == 0)
				return true;

			// Drop PS and NX from the 2MB PDE so the leftover bits 51:21 are a PFN,
			// then emit 512 4K PTEs covering the same host range. APM §5.3.4: a
			// 2-Mbyte page has no PT level until PS is cleared.
			const std::uint64_t base = pd[pdi] & ~page_2mb_mask & ~amd::npt_nx;
			const std::uint64_t flags = pd[pdi] & (amd::npt_rwx | amd::npt_nx);
			std::uint64_t* const pt = alloc_table();
			if (!pt)
				return false;

			for (std::uint32_t i = 0; i < 512; ++i)
				pt[i] = (base + static_cast<std::uint64_t>(i) * page_4kb_size) | (flags & ~amd::npt_large);

			pd[pdi] = nt::pa(pt) | amd::npt_rwx;
			return true;
		}

		std::uint64_t* pte(std::uint64_t gpa)
		{
			if (!m_pml4)
				return nullptr;

			const std::uint32_t pml4i = (gpa >> 39) & 0x1FF;
			const std::uint32_t pdpti = (gpa >> 30) & 0x1FF;
			const std::uint32_t pdi = (gpa >> 21) & 0x1FF;
			const std::uint32_t pti = (gpa >> 12) & 0x1FF;

			if ((m_pml4[pml4i] & amd::npt_present) == 0)
				return nullptr;

			auto* const pdpt = static_cast<std::uint64_t*>(va_from_pa(m_pml4[pml4i]));
			if ((pdpt[pdpti] & amd::npt_present) == 0 || (pdpt[pdpti] & amd::npt_large))
				return nullptr;

			auto* const pd = static_cast<std::uint64_t*>(va_from_pa(pdpt[pdpti]));
			if ((pd[pdi] & amd::npt_present) == 0 || (pd[pdi] & amd::npt_large))
				return nullptr;

			auto* const pt = static_cast<std::uint64_t*>(va_from_pa(pd[pdi]));
			return &pt[pti];
		}

		bool identity_fault(std::uint64_t gpa)
		{
			const std::uint64_t aligned = gpa & ~page_2mb_mask;
			return map_2mb(aligned, aligned, amd::npt_rwx);
		}

		std::uint64_t ncr3()
		{
			return nt::pa(m_pml4);
		}

		bool setup()
		{
			nt::ke_initialize_spin_lock(&m_lock);
			m_pml4 = alloc_table();
			if (!m_pml4)
				return false;

			PPHYSICAL_MEMORY_RANGE ranges = nt::mm_get_physical_memory_ranges();
			if (!ranges)
			{
				hv_log("MmGetPhysicalMemoryRanges failed");
				return false;
			}

			std::uint32_t mapped = 0;
			for (std::uint32_t i = 0; ranges[i].BaseAddress.QuadPart || ranges[i].NumberOfBytes.QuadPart; ++i)
			{
				// APM Vol. 2 (24593) §5.4.1: a 2-Mbyte page is aligned on a 2-Mbyte
				// boundary, so round the firmware range out to PDE.PS coverage.
				const std::uint64_t start = ranges[i].BaseAddress.QuadPart & ~page_2mb_mask;
				const std::uint64_t end =
					(ranges[i].BaseAddress.QuadPart + ranges[i].NumberOfBytes.QuadPart + page_2mb_mask) & ~page_2mb_mask;

				for (std::uint64_t pa = start; pa < end; pa += page_2mb_size)
				{
					if (!map_2mb(pa, pa, amd::npt_rwx))
					{
						hv_log("failed to map 2MB GPA %llx", pa);
						nt::free_pool(ranges);
						return false;
					}
					++mapped;
				}
			}

			nt::free_pool(ranges);
			hv_log("NPT identity-mapped %u 2MB pages, nCR3=%llx", mapped, ncr3());
			return true;
		}

		void cleanup()
		{
			for (std::uint32_t i = 0; i < m_page_count; ++i)
			{
				nt::free_contig(m_pages[i]);
				m_pages[i] = nullptr;
			}
			m_page_count = 0;
			m_pml4 = nullptr;
		}
	};

	c_npt g_npt;
}
