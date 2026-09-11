#pragma once

namespace nt
{
	inline constexpr ULONG pool_tag = ' hvH';

	inline void dbg_print(const char* fmt, ...)
	{
		using fn_t = ULONG(*)(ULONG, ULONG, PCSTR, va_list);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("vDbgPrintEx");
		if (!fn)
			return;

		va_list args;
		va_start(args, fmt);
		fn(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
		va_end(args);
	}

	inline BOOLEAN mm_is_address_valid(void* va)
	{
		using fn_t = BOOLEAN(*)(PVOID);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmIsAddressValid");
		if (!fn)
			return FALSE;
		return fn(va);
	}

	inline PHYSICAL_ADDRESS mm_get_physical_address(void* va)
	{
		using fn_t = PHYSICAL_ADDRESS(*)(PVOID);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmGetPhysicalAddress");
		if (!fn)
			return {};
		return fn(va);
	}

	inline void* mm_allocate_contiguous_memory_specify_cache(
		std::size_t bytes,
		PHYSICAL_ADDRESS low,
		PHYSICAL_ADDRESS high,
		PHYSICAL_ADDRESS boundary,
		MEMORY_CACHING_TYPE cache)
	{
		using fn_t = PVOID(*)(SIZE_T, PHYSICAL_ADDRESS, PHYSICAL_ADDRESS, PHYSICAL_ADDRESS, MEMORY_CACHING_TYPE);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmAllocateContiguousMemorySpecifyCache");
		if (!fn)
			return nullptr;
		return fn(bytes, low, high, boundary, cache);
	}

	inline void mm_free_contiguous_memory(void* va)
	{
		using fn_t = void(*)(PVOID);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmFreeContiguousMemory");
		if (fn && va)
			fn(va);
	}

	inline void* mm_get_virtual_for_physical(PHYSICAL_ADDRESS phys)
	{
		using fn_t = PVOID(*)(PHYSICAL_ADDRESS);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmGetVirtualForPhysical");
		if (!fn)
			return nullptr;
		return fn(phys);
	}

	inline PPHYSICAL_MEMORY_RANGE mm_get_physical_memory_ranges()
	{
		using fn_t = PPHYSICAL_MEMORY_RANGE(*)();
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmGetPhysicalMemoryRanges");
		if (!fn)
			return nullptr;
		return fn();
	}

	inline void* ex_allocate_pool(std::size_t bytes)
	{
		using zero_t = PVOID(*)(POOL_FLAGS, SIZE_T, ULONG);
		using pool2_t = PVOID(*)(POOL_FLAGS, SIZE_T, ULONG);
		using tag_t = PVOID(*)(POOL_TYPE, SIZE_T, ULONG);

		static zero_t zero_fn = nullptr;
		static pool2_t pool2_fn = nullptr;
		static tag_t tag_fn = nullptr;
		static bool resolved = false;
		if (!resolved)
		{
			zero_fn = g_resolver.get_system_routine<zero_t>("ExAllocatePoolZero");
			pool2_fn = g_resolver.get_system_routine<pool2_t>("ExAllocatePool2");
			tag_fn = g_resolver.get_system_routine<tag_t>("ExAllocatePoolWithTag");
			resolved = true;
		}

		void* va = nullptr;
		if (zero_fn)
			va = zero_fn(POOL_FLAG_NON_PAGED, bytes, pool_tag);
		else if (pool2_fn)
			va = pool2_fn(POOL_FLAG_NON_PAGED, bytes, pool_tag);
		else if (tag_fn)
			va = tag_fn(NonPagedPoolNx, bytes, pool_tag);

		if (va && !zero_fn)
			crt::memset(va, 0, bytes);
		return va;
	}

	inline void ex_free_pool(void* va)
	{
		using fn_t = void(*)(PVOID, ULONG);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("ExFreePoolWithTag");
		if (fn && va)
			fn(va, 0);
	}

	inline void ke_initialize_spin_lock(KSPIN_LOCK* lock)
	{
		if (lock)
			*lock = 0;
	}

	inline void ke_acquire_spin_lock(KSPIN_LOCK* lock, KIRQL* irql)
	{
		using fn_t = KIRQL(*)(PKSPIN_LOCK);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("KeAcquireSpinLockRaiseToDpc");
		if (!fn || !lock || !irql)
			return;
		*irql = fn(lock);
	}

	inline void ke_release_spin_lock(KSPIN_LOCK* lock, KIRQL irql)
	{
		using fn_t = void(*)(PKSPIN_LOCK, KIRQL);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("KeReleaseSpinLock");
		if (fn && lock)
			fn(lock, irql);
	}

	inline ULONG ke_query_active_processor_count_ex(USHORT group)
	{
		using fn_t = ULONG(*)(USHORT);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("KeQueryActiveProcessorCountEx");
		if (!fn)
			return 0;
		return fn(group);
	}

	inline NTSTATUS ke_get_processor_number_from_index(ULONG index, PPROCESSOR_NUMBER number)
	{
		using fn_t = NTSTATUS(*)(ULONG, PPROCESSOR_NUMBER);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("KeGetProcessorNumberFromIndex");
		if (!fn)
			return STATUS_UNSUCCESSFUL;
		return fn(index, number);
	}

	inline void ke_set_system_group_affinity_thread(PGROUP_AFFINITY next, PGROUP_AFFINITY previous)
	{
		using fn_t = void(*)(PGROUP_AFFINITY, PGROUP_AFFINITY);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("KeSetSystemGroupAffinityThread");
		if (fn)
			fn(next, previous);
	}

	inline void ke_revert_to_user_group_affinity_thread(PGROUP_AFFINITY previous)
	{
		using fn_t = void(*)(PGROUP_AFFINITY);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("KeRevertToUserGroupAffinityThread");
		if (fn)
			fn(previous);
	}

	inline ULONG ke_get_current_processor_number_ex(PPROCESSOR_NUMBER number)
	{
		using fn_t = ULONG(*)(PPROCESSOR_NUMBER);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("KeGetCurrentProcessorNumberEx");
		if (!fn)
			return 0;
		return fn(number);
	}

	inline bool resolve_core()
	{
		const char* required[] = {
			"vDbgPrintEx",
			"MmGetPhysicalAddress",
			"MmAllocateContiguousMemorySpecifyCache",
			"MmFreeContiguousMemory",
			"MmGetVirtualForPhysical",
			"MmGetPhysicalMemoryRanges",
			"ExFreePoolWithTag",
			"KeAcquireSpinLockRaiseToDpc",
			"KeReleaseSpinLock",
			"KeQueryActiveProcessorCountEx",
			"KeGetProcessorNumberFromIndex",
			"KeSetSystemGroupAffinityThread",
			"KeRevertToUserGroupAffinityThread",
			"KeGetCurrentProcessorNumberEx",
		};

		for (auto* name : required)
		{
			if (!g_resolver.get_system_routine(name))
				return false;
		}

		return g_resolver.get_system_routine("ExAllocatePoolZero")
			|| g_resolver.get_system_routine("ExAllocatePool2")
			|| g_resolver.get_system_routine("ExAllocatePoolWithTag");
	}

	inline bool is_manual_map(void* arg0, void* arg1)
	{
		struct map_ctx_t
		{
			std::uint64_t magic;
		};

		if (arg1 && mm_is_address_valid(arg1))
		{
			if (reinterpret_cast<map_ctx_t*>(arg1)->magic == 0x1337)
				return true;
		}

		if (!arg0)
			return true;

		if (!mm_is_address_valid(arg0))
			return true;

		if (reinterpret_cast<dos_header_t*>(arg0)->is_valid())
			return true;

		auto* const driver = static_cast<PDRIVER_OBJECT>(arg0);
		return driver->Type != IO_TYPE_DRIVER;
	}
}
