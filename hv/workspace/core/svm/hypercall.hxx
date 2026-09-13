#pragma once

#include <shared/hypercall.hxx>

namespace hv
{
	inline bool user_range(std::uint64_t va, std::uint64_t size)
	{
		if (!va || !size)
			return false;
		if (va > user_address_limit)
			return false;
		if (size - 1 > user_address_limit - va)
			return false;
		return true;
	}

	inline void* thread_initial_stack()
	{
		auto* const thread = reinterpret_cast<std::uint8_t*>(__readgsqword(0x188));
		if (!thread)
			return nullptr;
		return *reinterpret_cast<void**>(thread + 0x28);
	}

	inline std::size_t packet_size(std::uint64_t code)
	{
		switch (code)
		{
		case hc_ping:
			return sizeof(KERNEL_COPY_REQUEST);
		case hc_get_process:
			return sizeof(KERNEL_BASE_REQUEST);
		case hc_read:
			return sizeof(KERNEL_COPY_REQUEST);
		default:
			return 0;
		}
	}

	inline void advance_vmmcall(vcpu_t* vcpu)
	{
		if (vcpu->vmcb->ctrl.nrip && vcpu->vmcb->ctrl.nrip != vcpu->vmcb->state.rip)
			vcpu->vmcb->state.rip = vcpu->vmcb->ctrl.nrip;
		else
			vcpu->vmcb->state.rip += 3;
	}

	inline std::uint64_t guest_va_to_pa(std::uint64_t cr3, std::uint64_t virtual_address)
	{
		return mm::phys::va_to_pa(cr3, virtual_address);
	}

	// Packet in from CPL3: guest CR3 → PA → MmCopyMemory(copy_physical)
	// into a kernel struct. User VAs are not mapped in host CR3.
	inline bool guest_copy_in(std::uint64_t cr3, std::uint64_t va, void* dst, std::size_t size)
	{
		auto* out = static_cast<std::uint8_t*>(dst);
		while (size)
		{
			const std::uint64_t pa = guest_va_to_pa(cr3, va);
			if (!pa)
				return false;
			const std::size_t chunk = min(size, page_4kb_size - (pa & page_4kb_mask));
			if (mm::phys::read_direct(pa, out, chunk) != nt_status_t::success)
				return false;
			va += chunk;
			out += chunk;
			size -= chunk;
		}
		return true;
	}

	inline bool guest_copy_out(std::uint64_t cr3, std::uint64_t va, const void* src, std::size_t size)
	{
		auto* in = static_cast<std::uint8_t*>(const_cast<void*>(src));
		while (size)
		{
			const std::uint64_t pa = guest_va_to_pa(cr3, va);
			if (!pa)
			{
				nt::dbg_print("[guest_copy_out] va_to_pa failed va=0x%llx", va);
				return false;
			}

			const std::size_t chunk = min(size, page_4kb_size - (pa & page_4kb_mask));
			if (mm::phys::write_direct(pa, in, chunk) != nt_status_t::success)
			{
				nt::dbg_print("[guest_copy_out] write failed pa=0x%llx size=%zu window=%p",
					pa, chunk, mm::phys::g_window);
				return false;
			}

			if (chunk <= 32)
			{
				std::uint8_t verify[32]{};
				bool mismatch = mm::phys::read_direct(pa, verify, chunk) != nt_status_t::success;
				for (std::size_t i = 0; !mismatch && i < chunk; i++)
					mismatch = verify[i] != in[i];
				if (mismatch)
				{
					nt::dbg_print("[guest_copy_out] verify mismatch pa=0x%llx", pa);
					return false;
				}
			}

			va += chunk;
			in += chunk;
			size -= chunk;
		}
		return true;
	}

	__declspec(noinline) inline void run_hypercall(void* arg)
	{
		auto* const vcpu = static_cast<vcpu_t*>(arg);
		__writemsr(amd::msr_fs_base, vcpu->host_fs_base);
		__writemsr(amd::msr_gs_base, vcpu->host_gs_base);
		__writemsr(amd::msr_kernel_gs_base, vcpu->host_kernel_gs_base);
		__writeeflags(__readeflags() & ~amd::rflags_tf & ~amd::rflags_if);

		const std::uint64_t code = vcpu->vmcb->state.rax;
		const std::uint64_t pkt = vcpu->guest_rcx;
		const bool user = vcpu->vmcb->state.cpl != 0;
		const std::size_t raw_size = packet_size(code);

		nt::dbg_print("[hc] enter code=%llx cpl=%u\n", code, vcpu->vmcb->state.cpl);

		std::uint64_t result = hc_fail;
		KERNEL_BASE_REQUEST base_req{};
		KERNEL_COPY_REQUEST copy_req{};
		void* host_pkt = nullptr;
		bool write_back = false;

		if (!raw_size)
		{
			vcpu->vmcb->state.rax = hc_fail;
			advance_vmmcall(vcpu);
			return;
		}

		if (user)
		{
			if (code == hc_get_process)
			{
				host_pkt = &base_req;
			}
			else
			{
				if (!pkt || !user_range(pkt, raw_size))
				{
					vcpu->vmcb->state.rax = hc_fail;
					advance_vmmcall(vcpu);
					return;
				}
				if (!guest_copy_in(vcpu->vmcb->state.cr3, pkt, &copy_req, sizeof(copy_req)))
				{
					vcpu->vmcb->state.rax = hc_fail;
					advance_vmmcall(vcpu);
					return;
				}
				host_pkt = &copy_req;
			}
		}
		else
		{
			if (!pkt)
			{
				vcpu->vmcb->state.rax = hc_fail;
				advance_vmmcall(vcpu);
				return;
			}
			host_pkt = reinterpret_cast<void*>(pkt);
		}

		switch (code)
		{
		case hc_ping:
		{
			result = hc_magic;
			break;
		}

		case hc_get_process:
		{
			auto* const req = reinterpret_cast<PKERNEL_BASE_REQUEST>(host_pkt);
			const auto current_pid = nt::ps_get_current_process_id();
			if (user)
			{
				if (req->ProcessId && req->ProcessId != current_pid)
					break;
				req->ProcessId = current_pid;
			}

			if (process::get_process_base_addr(req) != nt_status_t::success)
				break;
			result = req->ProcessBase;
			vcpu->guest_rdx = req->DTB;
			break;
		}

		case hc_read:
		{
			auto* const req = reinterpret_cast<PKERNEL_COPY_REQUEST>(host_pkt);
			if (!req->size || req->size > hc_max_copy)
				break;
			if (user && !user_range(req->address, req->size))
				break;
			if (req->buffer)
			{
				if (user && !user_range(reinterpret_cast<std::uint64_t>(req->buffer), req->size))
					break;
			}
			else if (req->size > sizeof(std::uint64_t))
				break;
			if (!mm::g_paging.get_dtb())
				break;
			if (memory::read_virtual(req, user ? vcpu->vmcb->state.cr3 : 0) != nt_status_t::success)
				break;
			if (req->size <= sizeof(std::uint64_t))
			{
				std::uint64_t value = 0;
				nt::copy_memory(&value, mm::g_paging.m_copy_scratch, static_cast<std::size_t>(req->size));
				vcpu->guest_rdx = value;
			}
			result = req->size;
			break;
		}

		default:
			break;
		}

		if (write_back && !guest_copy_out(vcpu->vmcb->state.cr3, pkt, host_pkt, raw_size))
			nt::dbg_print("[hc] copy-out failed (using rax/rdx)");

		vcpu->vmcb->state.rax = result;
		advance_vmmcall(vcpu);
	}

	inline void handle_vmmcall(vcpu_t* vcpu)
	{
		vcpu->vmcb->state.rflags &= ~amd::rflags_tf;
		__writeeflags(__readeflags() & ~amd::rflags_tf);

		if (vcpu->vmcb->state.rax == hc_ping)
		{
			vcpu->vmcb->state.rax = hc_magic;
			advance_vmmcall(vcpu);
			return;
		}

		if (vcpu->vmcb->state.cpl != 0)
		{
			hv_run_with_nt(&run_hypercall, vcpu);
			return;
		}
		run_hypercall(vcpu);
	}
}
