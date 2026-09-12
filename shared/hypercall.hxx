#pragma once

namespace hv
{
	inline constexpr unsigned long long hc_magic = 0x4856;
	inline constexpr unsigned long long hc_ping = 1;
	inline constexpr unsigned long long hc_get_process = 2;
	inline constexpr unsigned long long hc_read = 3;
	inline constexpr unsigned long long hc_fail = ~0ull;
	inline constexpr unsigned long long hc_max_copy = 0x1000;
}

typedef struct _KERNEL_BASE_REQUEST {
	UINT32 ProcessId;
	UINT64 ProcessBase;
	UINT64 DTB;
} KERNEL_BASE_REQUEST, *PKERNEL_BASE_REQUEST;

typedef struct _KERNEL_COPY_REQUEST {
	UINT32 pid;
	uintptr_t address;
	PVOID buffer;
	uintptr_t size;
	bool m_do_translate;
} KERNEL_COPY_REQUEST, *PKERNEL_COPY_REQUEST;
