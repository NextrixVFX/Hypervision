#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <shared/hypercall.hxx>

extern "C" unsigned long long hv_vmmcall(
	unsigned long long code,
	void* req,
	unsigned long long* aux);

#pragma pack(push, 1)
struct dos_probe
{
	std::uint16_t e_magic;
	std::uint16_t e_cblp;
	std::uint16_t e_cp;
	std::uint16_t e_crlc;
	std::uint16_t e_cparhdr;
	std::uint16_t e_minalloc;
	std::uint16_t e_maxalloc;
	std::uint16_t e_ss;
	std::uint16_t e_sp;
	std::uint16_t e_csum;
	std::uint16_t e_ip;
	std::uint16_t e_cs;
	std::uint16_t e_lfarlc;
	std::uint16_t e_ovno;
	std::uint16_t e_res[4];
	std::uint16_t e_oemid;
	std::uint16_t e_oeminfo;
	std::uint16_t e_res2[10];
	std::int32_t e_lfanew;
};
#pragma pack(pop)

static bool ping()
{
	KERNEL_COPY_REQUEST req{};
	__try
	{
		return hv_vmmcall(hv::hc_ping, &req, nullptr) == hv::hc_magic;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

static bool get_process_base(KERNEL_BASE_REQUEST* req)
{
	req->ProcessId = GetCurrentProcessId();
	unsigned long long dtb = 0;
	const unsigned long long base = hv_vmmcall(hv::hc_get_process, req, &dtb);
	if (!req->ProcessBase && base && base != hv::hc_fail)
		req->ProcessBase = base;
	if (!req->DTB && dtb && dtb != hv::hc_fail)
		req->DTB = dtb;
	return req->ProcessBase && req->DTB;
}

static unsigned long long read_bytes(std::uintptr_t src, void* dst, std::uintptr_t size)
{
	KERNEL_COPY_REQUEST req{};
	req.address = src;
	req.buffer = dst;
	req.size = size;
	req.m_do_translate = true;
	return hv_vmmcall(hv::hc_read, &req, nullptr);
}

static unsigned long long read_qword(std::uintptr_t src, unsigned long long* value)
{
	KERNEL_COPY_REQUEST req{};
	req.address = src;
	req.buffer = nullptr;
	req.size = 8;
	req.m_do_translate = true;
	return hv_vmmcall(hv::hc_read, &req, value);
}

static bool read_struct(std::uint64_t image_base)
{
	dos_probe dos{};
	const unsigned long long n = read_bytes(image_base, &dos, sizeof(dos));
	std::printf("struct dos_probe size=%zu n=0x%llx mz=0x%04x lfanew=0x%x\n",
		sizeof(dos), n, dos.e_magic, dos.e_lfanew);
	return n == sizeof(dos) && dos.e_magic == 0x5A4D && dos.e_lfanew != 0;
}

static void dump_image_page(std::uint64_t image_base)
{
	std::printf("reading [0x%llx, 0x%llx)\n", image_base, image_base + 0x1000);

	unsigned long long first = 0;
	unsigned long long ok = 0;
	unsigned long long fail = 0;

	for (std::uint64_t off = 0; off < 0x1000; off += 8)
	{
		unsigned long long value = 0;
		const unsigned long long n = read_qword(image_base + off, &value);
		if (n != 8)
		{
			++fail;
			std::printf("  fail va=0x%llx n=0x%llx\n", image_base + off, n);
			continue;
		}
		++ok;
		if (off == 0)
			first = value;
		if (off < 0x40 || (off & 0xFF) == 0)
			std::printf("  +0x%03llx: 0x%016llx\n", off, value);
	}

	std::printf("page: %llu ok, %llu fail, first=0x%llx (mz=%s)\n",
		ok, fail, first, (first & 0xFFFF) == 0x5A4D ? "yes" : "no");
}

int main()
{
	if (!ping())
	{
		std::printf("VMMCALL ping failed (hypervisor not running, or #UD)\n");
		system("pause");
		return 1;
	}
	std::printf("ping ok\n");
	system("pause");
	KERNEL_BASE_REQUEST base{};
	if (!get_process_base(&base))
	{
		std::printf("get process base failed pid=%lu base=0x%llx dtb=0x%llx\n",
			base.ProcessId, base.ProcessBase, base.DTB);
		system("pause");
		return 1;
	}
	std::printf("pid=%lu base=0x%llx dtb=0x%llx\n",
		base.ProcessId, base.ProcessBase, base.DTB);
	system("pause");
	if (!read_struct(base.ProcessBase))
	{
		std::printf("struct read failed\n");
		system("pause");
		return 1;
	}
	system("pause");
	dump_image_page(base.ProcessBase);
	system("pause");
	return 0;
}
