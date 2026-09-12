#pragma once

#include <shared/hypercall.hxx>

namespace process
{
	inline std::uint32_t g_resolved_pid{};

	__declspec(noinline) inline nt_status_t get_process_base_addr(PKERNEL_BASE_REQUEST req)
	{
		if (nt::ke_get_current_irql() != PASSIVE_LEVEL)
			return nt_status_t::invalid_device_state;

		if (!req || !req->ProcessId)
			return nt_status_t::invalid_parameter;

		nt::dbg_print("[get_process_base_addr] begin pid=%lu", req->ProcessId);

		eprocess_t* process = nt::ps_lookup_process_by_pid(static_cast<std::uint32_t>(req->ProcessId));
		if (!process)
		{
			nt::dbg_print("[get_process_base_addr] process: Couldn't locate process by PID! pid=%lu", req->ProcessId);
			return nt_status_t::unsuccessful;
		}

		const uint64_t base_addr = reinterpret_cast<uint64_t>(nt::ps_get_process_section_base_address(process));
		if (!base_addr)
		{
			nt::dbg_print("[get_process_base_addr] base_addr: Couldn't locate process base address! base_addr=0x%llx", base_addr);
			nt::ob_dereference_object(process);
			return nt_status_t::unsuccessful;
		}

		nt::dbg_print("[get_process_base_addr] Found Base address: 0x%llx", base_addr);
		req->ProcessBase = base_addr;

		if (!mm::g_paging.scan_pages(base_addr, 0x5A4D))
		{
			nt::dbg_print("[get_process_base_addr] scan_pages: Couldn't scan pages!");
			nt::ob_dereference_object(process);
			return nt_status_t::unsuccessful;
		}

		const uint64_t dtb = mm::g_paging.get_dtb();
		if (!dtb)
		{
			nt::dbg_print("[get_process_base_addr] dtb: Couldn't locate process dtb! dtb=0x%llx", dtb);
			nt::ob_dereference_object(process);
			return nt_status_t::unsuccessful;
		}

		nt::dbg_print("[get_process_base_addr] Found DTB: 0x%llx", dtb);
		req->DTB = dtb;
		g_resolved_pid = req->ProcessId;

		nt::ob_dereference_object(process);
		return nt_status_t::success;
	}

	inline bool ensure_dtb(std::uint32_t pid)
	{
		if (!pid)
			return false;
		if (mm::g_paging.get_dtb() && g_resolved_pid == pid)
			return true;

		KERNEL_BASE_REQUEST req{};
		req.ProcessId = pid;
		return get_process_base_addr(&req) == nt_status_t::success;
	}
}

namespace memory
{
	inline bool copy_out_dest(void* dest, std::uint64_t dest_va, std::uint64_t dest_cr3, void* src, std::size_t size)
	{
		if (dest_cr3)
		{
			const std::uint64_t dest_pa = mm::phys::va_to_pa(dest_cr3, dest_va);
			if (!dest_pa)
				return false;
			return mm::phys::write_direct(dest_pa, src, size) == nt_status_t::success;
		}

		if (dest && nt::mm_is_address_valid(dest))
		{
			nt::rtl_copy_memory(dest, src, size);
			return true;
		}

		return false;
	}

	__declspec(noinline) inline nt_status_t read_virtual(PKERNEL_COPY_REQUEST req, std::uint64_t dest_cr3 = 0)
	{
		if (nt::ke_get_current_irql() != PASSIVE_LEVEL)
			return nt_status_t::invalid_device_state;

		if (!req->address || !req->size)
			return nt_status_t::invalid_parameter;
		if (!req->buffer && req->size > 8)
			return nt_status_t::invalid_parameter;

		std::size_t remaining = req->size;
		uintptr_t va = req->address;
		auto* out = static_cast<std::uint8_t*>(req->buffer);
		const auto out_va = reinterpret_cast<std::uintptr_t>(req->buffer);
		const bool copy_out = req->buffer != nullptr;

		while (remaining)
		{
			uintptr_t src_pa = va;
			if (req->m_do_translate)
			{
				src_pa = mm::g_paging.translate(va);
				if (!src_pa)
				{
					nt::dbg_print("[read_virtual] translation failed! va=0x%llx", va);
					return nt_status_t::unsuccessful;
				}
			}
			else if (dest_cr3)
			{
				src_pa = mm::phys::va_to_pa(dest_cr3, va);
				if (!src_pa)
					return nt_status_t::unsuccessful;
			}

			std::size_t chunk = min(remaining, page_4kb_size - (src_pa & page_4kb_mask));
			if (copy_out && dest_cr3)
			{
				const std::uint64_t dest_pa = mm::phys::va_to_pa(dest_cr3, out_va + (req->size - remaining));
				if (!dest_pa)
					return nt_status_t::unsuccessful;
				chunk = min(chunk, page_4kb_size - (dest_pa & page_4kb_mask));
			}
			if (chunk > sizeof(mm::g_paging.m_copy_scratch))
				return nt_status_t::unsuccessful;

			if (remaining == req->size)
				nt::dbg_print("[read_virtual] va=0x%llx pa=0x%llx chunk=%zu", va, src_pa, chunk);
			const auto status = mm::phys::read_physical(src_pa, mm::g_paging.m_copy_scratch, chunk);
			if (status != nt_status_t::success)
			{
				nt::dbg_print("[read_virtual] read failed! va=0x%llx pa=0x%llx", va, src_pa);
				return status;
			}

			if (copy_out && !copy_out_dest(out, out_va + (req->size - remaining), dest_cr3,
				mm::g_paging.m_copy_scratch, chunk))
			{
				nt::dbg_print("[read_virtual] copy_out failed va=0x%llx pa=0x%llx", va, src_pa);
				if (req->size <= 8 && remaining == req->size)
					return nt_status_t::success;
				return nt_status_t::unsuccessful;
			}

			va += chunk;
			if (out)
				out += chunk;
			remaining -= chunk;
		}

		return nt_status_t::success;
	}

	inline nt_status_t write_virtual(PKERNEL_COPY_REQUEST req)
	{
		if (nt::ke_get_current_irql() != PASSIVE_LEVEL)
			return nt_status_t::invalid_device_state;

		if (!req->address || !req->buffer || !req->size)
			return nt_status_t::invalid_parameter;

		std::size_t remaining = req->size;
		uintptr_t va = req->address;
		auto* in = static_cast<std::uint8_t*>(req->buffer);

		while (remaining)
		{
			const uint64_t physical_address = mm::g_paging.translate(va);
			if (!physical_address)
			{
				nt::dbg_print("[write_virtual] physical_address: translation failed");
				return nt_status_t::unsuccessful;
			}

			const std::size_t page_offset = physical_address & page_4kb_mask;
			const std::size_t chunk = min(remaining, page_4kb_size - page_offset);
			size_t submitted_bytes = 0;
			if (mm::phys::write_direct(physical_address, in, chunk, &submitted_bytes) != nt_status_t::success)
				return nt_status_t::unsuccessful;

			va += chunk;
			in += chunk;
			remaining -= chunk;
		}

		return nt_status_t::success;
	}
}
