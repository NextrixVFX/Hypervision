#pragma once

namespace nt
{
	inline void zero_memory(void* dest, std::size_t bytes)
	{
		if (dest && bytes)
			crt::memset(dest, 0, bytes);
	}

	inline void copy_memory(void* dest, const void* src, std::size_t bytes)
	{
		if (dest && src && bytes)
			crt::memcpy(dest, src, bytes);
	}

	inline std::uint64_t pa(void* va)
	{
		return mm_get_physical_address(va).QuadPart;
	}

	inline void* alloc_contig(std::size_t bytes)
	{
		PHYSICAL_ADDRESS low{};
		PHYSICAL_ADDRESS high{};
		high.QuadPart = ~0ULL;
		void* const va = mm_allocate_contiguous_memory_specify_cache(
			bytes,
			low,
			high,
			low,
			MmCached);
		if (va)
			zero_memory(va, bytes);
		return va;
	}

	inline void free_contig(void* va)
	{
		mm_free_contiguous_memory(va);
	}

	inline void* alloc_pool(std::size_t bytes)
	{
		return ex_allocate_pool(bytes);
	}

	inline void free_pool(void* va)
	{
		ex_free_pool(va);
	}
}
