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

	mmpfn_t* get_mm_pfn_database() {
		static mmpfn_t* mm_pfn_database = nullptr;
		if (!mm_pfn_database) {
			static unsigned char* function_address = nullptr;
			if (!function_address) {
				function_address = (unsigned char*)g_resolver.lookup_export("KeCapturePersistentThreadState");
				if (!function_address) return { };
			}

			while (function_address[0x0] != 0x48
				|| function_address[0x1] != 0x8B
				|| function_address[0x2] != 0x05)
				function_address++;

			mm_pfn_database = *reinterpret_cast<mmpfn_t**>(
				&function_address[0x7] + *reinterpret_cast<std::int32_t*>(&function_address[0x3]));
		}

		return mm_pfn_database;
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

	inline NTSTATUS mm_copy_memory(
		void* dst,
		MM_COPY_ADDRESS src,
		std::size_t size,
		ULONG flags,
		std::size_t* transferred)
	{
		using fn_t = NTSTATUS(*)(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmCopyMemory");
		if (!fn || !transferred)
			return STATUS_UNSUCCESSFUL;
		return fn(dst, src, size, flags, transferred);
	}

	inline void* mm_map_io_space_ex(PHYSICAL_ADDRESS phys, std::size_t size, ULONG protect)
	{
		using fn_t = PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, ULONG);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmMapIoSpaceEx");
		if (!fn)
			return nullptr;
		return fn(phys, size, protect);
	}

	inline void mm_unmap_io_space(void* va, std::size_t size)
	{
		using fn_t = void(*)(PVOID, SIZE_T);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmUnmapIoSpace");
		if (fn && va)
			fn(va, size);
	}

	inline PMDL mm_allocate_pages_for_mdl(PHYSICAL_ADDRESS low, PHYSICAL_ADDRESS high, PHYSICAL_ADDRESS skip, std::size_t bytes)
	{
		using fn_t = PMDL(*)(PHYSICAL_ADDRESS, PHYSICAL_ADDRESS, PHYSICAL_ADDRESS, SIZE_T);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmAllocatePagesForMdl");
		if (!fn)
			return nullptr;
		return fn(low, high, skip, bytes);
	}

	inline void* mm_map_locked_pages_specify_cache(PMDL mdl, KPROCESSOR_MODE mode, MEMORY_CACHING_TYPE cache, void* requested, BOOLEAN bugcheck, ULONG priority)
	{
		using fn_t = PVOID(*)(PMDL, KPROCESSOR_MODE, MEMORY_CACHING_TYPE, PVOID, BOOLEAN, ULONG);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmMapLockedPagesSpecifyCache");
		if (!fn || !mdl)
			return nullptr;
		return fn(mdl, mode, cache, requested, bugcheck, priority);
	}

	inline void mm_unmap_locked_pages(void* va, PMDL mdl)
	{
		using fn_t = void(*)(PVOID, PMDL);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmUnmapLockedPages");
		if (fn && va && mdl)
			fn(va, mdl);
	}

	inline void mm_free_pages_from_mdl(PMDL mdl)
	{
		using fn_t = void(*)(PMDL);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("MmFreePagesFromMdl");
		if (fn && mdl)
			fn(mdl);
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

	std::uint8_t ke_get_current_irql() {
		return static_cast<std::uint8_t>(__readcr8());
	}

	void rtl_move_memory(void* dest, const void* src, size_t length) {
		static auto function_address = 0ull;
		if (!function_address) {
			function_address = g_resolver.get_system_routine("RtlMoveMemory");
			if (!function_address) return;
		}

		using function_t = void (*)(void*, const void*, size_t);
		reinterpret_cast<function_t>(function_address)(dest, src, length);
	}

	void rtl_zero_memory(void* destination, std::size_t length) {
		static std::uint64_t function_addr = 0;

		if (!function_addr)
			function_addr = g_resolver.get_system_routine("RtlZeroMemory");

		using fn_t = void(*)(void*, std::size_t);
		reinterpret_cast<fn_t>(function_addr)(destination, length);
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

	inline void rtl_copy_memory(
		void* dest,
		const void* src,
		size_t length
	)
	{
		using fn_t = void(*)(void*,
			const void*,
			size_t);

		static fn_t fn = nullptr;

		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("RtlCopyMemory");

		if (fn)
			fn(dest,
				src,
				length);
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

	inline std::uint32_t ps_get_current_process_id()
	{
		using fn_t = HANDLE(*)();
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("PsGetCurrentProcessId");
		if (!fn)
			return 0;
		return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(fn()));
	}

	inline eprocess_t* ps_lookup_process_by_pid(std::uint32_t process_id)
	{
		using fn_t = NTSTATUS(*)(HANDLE, eprocess_t**);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("PsLookupProcessByProcessId");
		if (!fn)
			return nullptr;

		eprocess_t* process = nullptr;
		if (fn(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(process_id)), &process) != STATUS_SUCCESS)
			return nullptr;
		return process;
	}

	inline void* ps_get_process_section_base_address(eprocess_t* process)
	{
		using fn_t = void*(*)(eprocess_t*);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("PsGetProcessSectionBaseAddress");
		if (!fn || !process)
			return nullptr;
		return fn(process);
	}

	inline void ob_dereference_object(void* object)
	{
		using fn_t = void(*)(void*);
		static fn_t fn = nullptr;
		if (!fn)
			fn = g_resolver.get_system_routine<fn_t>("ObDereferenceObject");
		if (fn && object)
			fn(object);
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
			"PsGetCurrentProcessId",
			"PsLookupProcessByProcessId",
			"PsGetProcessSectionBaseAddress",
			"ObDereferenceObject",
			"MmCopyMemory",
			"MmIsAddressValid",
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
