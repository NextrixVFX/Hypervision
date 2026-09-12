#pragma once

namespace npt
{
	class c_npt
	{
		void* m_pages[npt_max_pages];
		std::uint64_t m_page_pas[npt_max_pages];
		void* m_spare[npt_spare_pages];
		std::uint64_t m_spare_pas[npt_spare_pages];
		std::uint32_t m_page_count;
		std::uint32_t m_spare_count;
		std::uint64_t* m_pml4;
		std::uint64_t m_ncr3;
		bool m_can_alloc;

	public:
		volatile LONG m_busy;

		std::uint64_t table_pa(void* page)
		{
			for (std::uint32_t i = 0; i < m_page_count; ++i)
			{
				if (m_pages[i] == page)
					return m_page_pas[i];
			}
			return 0;
		}

		std::uint64_t* alloc_table()
		{
			if (m_page_count >= npt_max_pages)
				return nullptr;

			void* page = nullptr;
			std::uint64_t page_pa = 0;
			if (m_spare_count)
			{
				--m_spare_count;
				page = m_spare[m_spare_count];
				page_pa = m_spare_pas[m_spare_count];
				m_spare[m_spare_count] = nullptr;
				m_spare_pas[m_spare_count] = 0;
			}
			else if (m_can_alloc)
			{
				page = nt::alloc_contig(page_4kb_size);
				if (!page)
					return nullptr;
				page_pa = nt::pa(page) & ~page_4kb_mask;
			}
			else
			{
				return nullptr;
			}

			m_pages[m_page_count] = page;
			m_page_pas[m_page_count] = page_pa;
			++m_page_count;
			return static_cast<std::uint64_t*>(page);
		}

		void stock_spares()
		{
			while (m_spare_count < npt_spare_pages)
			{
				if (m_page_count + m_spare_count >= npt_max_pages)
					break;
				void* const page = nt::alloc_contig(page_4kb_size);
				if (!page)
					break;
				m_spare_pas[m_spare_count] = nt::pa(page) & ~page_4kb_mask;
				m_spare[m_spare_count++] = page;
			}
		}

		void* va_from_pa(std::uint64_t pa)
		{
			// APM Vol. 2 (24593) §5.4.1: physical-page numbers sit in bits 51:12;
			// NX is bit 63 of the same qword, so it must be stripped before treating
			// the entry as a host physical address. Look up our own contig tables —
			// MmGetVirtualForPhysical on a page-table PFN is a classic 0x50.
			const std::uint64_t page_pa = pa & ~page_4kb_mask & ~amd::npt_nx;
			for (std::uint32_t i = 0; i < m_page_count; ++i)
			{
				if (m_page_pas[i] == page_pa)
					return m_pages[i];
			}
			return nullptr;
		}

		bool walk_map(std::uint64_t gpa, std::uint64_t hpa, std::uint64_t flags, bool large)
		{
			if (!m_pml4)
				return false;

			const std::uint32_t pml4i = (gpa >> 39) & 0x1FF;
			const std::uint32_t pdpti = (gpa >> 30) & 0x1FF;
			const std::uint32_t pdi = (gpa >> 21) & 0x1FF;
			const std::uint32_t pti = (gpa >> 12) & 0x1FF;

			if ((m_pml4[pml4i] & amd::npt_present) == 0)
			{
				std::uint64_t* const pdpt = alloc_table();
				if (!pdpt)
					return false;
				m_pml4[pml4i] = table_pa(pdpt) | amd::npt_rwx;
			}

			auto* const pdpt = static_cast<std::uint64_t*>(va_from_pa(m_pml4[pml4i]));
			if (!pdpt)
				return false;
			if ((pdpt[pdpti] & amd::npt_present) == 0)
			{
				std::uint64_t* const pd = alloc_table();
				if (!pd)
					return false;
				pdpt[pdpti] = table_pa(pd) | amd::npt_rwx;
			}
			else if (pdpt[pdpti] & amd::npt_large)
			{
				return false;
			}

			auto* const pd = static_cast<std::uint64_t*>(va_from_pa(pdpt[pdpti]));
			if (!pd)
				return false;
			if (large)
			{
				// A 4K PT means this 2MB was split for a hook. Replacing it with
				// PS=1 restores identity RAM and drops the execute shadow.
				if ((pd[pdi] & amd::npt_present) && (pd[pdi] & amd::npt_large) == 0)
					return false;
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
				pd[pdi] = table_pa(pt) | amd::npt_rwx;
			}

			auto* const pt = static_cast<std::uint64_t*>(va_from_pa(pd[pdi]));
			if (!pt)
				return false;
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
			if (!pdpt)
				return false;
			if ((pdpt[pdpti] & amd::npt_present) == 0)
				return map_4k(gpa, gpa, amd::npt_rwx);

			auto* const pd = static_cast<std::uint64_t*>(va_from_pa(pdpt[pdpti]));
			if (!pd)
				return false;
			if ((pd[pdi] & amd::npt_present) == 0)
				return map_4k(gpa, gpa, amd::npt_rwx);

			if ((pd[pdi] & amd::npt_large) == 0)
				return true;

			const std::uint64_t base = pd[pdi] & ~page_2mb_mask & ~amd::npt_nx;
			const std::uint64_t flags = pd[pdi] & (amd::npt_rwx | amd::npt_nx);
			std::uint64_t* const pt = alloc_table();
			if (!pt)
				return false;

			for (std::uint32_t i = 0; i < 512; ++i)
				pt[i] = (base + static_cast<std::uint64_t>(i) * page_4kb_size) | (flags & ~amd::npt_large);

			pd[pdi] = table_pa(pt) | amd::npt_rwx;
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
			if (!pdpt || (pdpt[pdpti] & amd::npt_present) == 0 || (pdpt[pdpti] & amd::npt_large))
				return nullptr;

			auto* const pd = static_cast<std::uint64_t*>(va_from_pa(pdpt[pdpti]));
			if (!pd || (pd[pdi] & amd::npt_present) == 0 || (pd[pdi] & amd::npt_large))
				return nullptr;

			auto* const pt = static_cast<std::uint64_t*>(va_from_pa(pd[pdi]));
			if (!pt)
				return nullptr;
			return &pt[pti];
		}

		bool identity_fault(std::uint64_t gpa)
		{
			const std::uint64_t aligned = gpa & ~page_2mb_mask;
			if (map_2mb(aligned, aligned, amd::npt_rwx))
				return true;

			const std::uint64_t page = gpa & ~page_4kb_mask;
			if (!split_2mb(gpa))
				return false;
			return map_4k(page, page, amd::npt_rwx);
		}

		std::uint64_t ncr3()
		{
			return m_ncr3;
		}

		bool setup()
		{
			m_busy = 0;
			m_can_alloc = true;
			m_ncr3 = 0;
			m_page_count = 0;
			m_spare_count = 0;
			m_pml4 = nullptr;
			nt::zero_memory(m_pages, sizeof(m_pages));
			nt::zero_memory(m_page_pas, sizeof(m_page_pas));
			nt::zero_memory(m_spare, sizeof(m_spare));
			nt::zero_memory(m_spare_pas, sizeof(m_spare_pas));

			m_pml4 = alloc_table();
			m_ncr3 = table_pa(m_pml4);
			if (!m_pml4 || !m_ncr3)
				return false;

			PPHYSICAL_MEMORY_RANGE ranges = nt::mm_get_physical_memory_ranges();
			if (!ranges)
			{
				hv_log("MmGetPhysicalMemoryRanges failed");
				return false;
			}

			std::uint32_t mapped_2m = 0;
			std::uint32_t mapped_4k = 0;
			for (std::uint32_t i = 0; ranges[i].BaseAddress.QuadPart || ranges[i].NumberOfBytes.QuadPart; ++i)
			{
				const std::uint64_t range_base = static_cast<std::uint64_t>(ranges[i].BaseAddress.QuadPart);
				const std::uint64_t range_end = range_base + static_cast<std::uint64_t>(ranges[i].NumberOfBytes.QuadPart);
				const std::uint64_t start = (range_base + page_2mb_mask) & ~page_2mb_mask;
				const std::uint64_t end = range_end & ~page_2mb_mask;

				for (std::uint64_t pa = start; pa < end; pa += page_2mb_size)
				{
					if (!map_2mb(pa, pa, amd::npt_rwx))
					{
						hv_log("failed to map 2MB GPA %llx", pa);
						nt::free_pool(ranges);
						return false;
					}
					++mapped_2m;
				}

				const std::uint64_t head_end = (start < end) ? start : range_end;
				for (std::uint64_t pa = range_base & ~page_4kb_mask; pa < head_end && pa + page_4kb_size <= range_end; pa += page_4kb_size)
				{
					if (pa < range_base)
						continue;
					if (map_4k(pa, pa, amd::npt_rwx))
						++mapped_4k;
				}

				if (start < end)
				{
					for (std::uint64_t pa = end; pa + page_4kb_size <= range_end; pa += page_4kb_size)
					{
						if (map_4k(pa, pa, amd::npt_rwx))
							++mapped_4k;
					}
				}
			}

			nt::free_pool(ranges);
			stock_spares();
			m_can_alloc = false;
			hv_log("NPT identity-mapped %u 2MB + %u 4K, spare=%u nCR3=%llx",
				mapped_2m, mapped_4k, m_spare_count, ncr3());
			return true;
		}

		void cleanup()
		{
			for (std::uint32_t i = 0; i < m_page_count; ++i)
			{
				nt::free_contig(m_pages[i]);
				m_pages[i] = nullptr;
				m_page_pas[i] = 0;
			}
			for (std::uint32_t i = 0; i < m_spare_count; ++i)
			{
				nt::free_contig(m_spare[i]);
				m_spare[i] = nullptr;
			}
			m_page_count = 0;
			m_spare_count = 0;
			m_pml4 = nullptr;
			m_ncr3 = 0;
		}
	};

	c_npt g_npt;
}
