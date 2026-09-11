#pragma once

namespace hv
{
	inline void advance_rip(vcpu_t* vcpu)
	{
		if (vcpu->vmcb->ctrl.nrip)
			vcpu->vmcb->state.rip = vcpu->vmcb->ctrl.nrip;
	}

	inline void handle_cpuid(vcpu_t* vcpu)
	{
		int regs[4]{};
		__cpuidex(
			regs,
			static_cast<int>(vcpu->vmcb->state.rax),
			static_cast<int>(vcpu->guest_rcx));

		const std::uint32_t leaf = static_cast<std::uint32_t>(vcpu->vmcb->state.rax);
		if (leaf == 1)
			regs[2] |= static_cast<int>(amd::cpuid_hypervisor);
		else if (leaf == 0x80000001)
			regs[2] &= ~static_cast<int>(amd::cpuid_svm);
		else if (leaf == 0x40000000)
		{
			regs[0] = 0x40000001;
			regs[1] = 0x65707948;
			regs[2] = 0x73697672;
			regs[3] = 0x216E6F69;
		}

		vcpu->vmcb->state.rax = static_cast<std::uint32_t>(regs[0]);
		vcpu->guest_rbx = static_cast<std::uint32_t>(regs[1]);
		vcpu->guest_rcx = static_cast<std::uint32_t>(regs[2]);
		vcpu->guest_rdx = static_cast<std::uint32_t>(regs[3]);
		advance_rip(vcpu);
	}

	inline void handle_msr(vcpu_t* vcpu)
	{
		// SVM Architecture Reference (33047) §2.7:
		// "On #VMEXIT, the processor indicates in the VMCB's EXITINFO1 whether a
		// RDMSR (EXITINFO1 = 0) or WRMSR (EXITINFO1 = 1) was intercepted."
		const bool write = (vcpu->vmcb->ctrl.exit_info1 & 1) != 0;
		const std::uint32_t msr = static_cast<std::uint32_t>(vcpu->guest_rcx);
		// WRMSR/RDMSR value is EDX:EAX; VMCB.RAX holds EAX, guest_rdx holds EDX.
		std::uint64_t value = (vcpu->guest_rdx << 32) | static_cast<std::uint32_t>(vcpu->vmcb->state.rax);

		if (write)
		{
			switch (msr)
			{
			case amd::msr_efer:
				vcpu->vmcb->state.efer = value | amd::efer_svme;
				break;
			case amd::msr_vm_cr:
			case amd::msr_vm_hsave_pa:
				break;
			default:
				__writemsr(msr, value);
				break;
			}
		}
		else
		{
			switch (msr)
			{
			case amd::msr_efer:
				value = vcpu->vmcb->state.efer;
				break;
			case amd::msr_vm_cr:
			case amd::msr_vm_hsave_pa:
				value = 0;
				break;
			default:
				value = __readmsr(msr);
				break;
			}
			vcpu->vmcb->state.rax = static_cast<std::uint32_t>(value);
			vcpu->guest_rdx = value >> 32;
		}
		advance_rip(vcpu);
	}

	inline void handle_npf(vcpu_t* vcpu)
	{
		const std::uint64_t info1 = vcpu->vmcb->ctrl.exit_info1;
		const std::uint64_t gpa = vcpu->vmcb->ctrl.exit_info2;

		KIRQL irql{};
		nt::ke_acquire_spin_lock(&npt::g_npt.m_lock, &irql);
		if (split::owns(gpa))
		{
			split::handle_npf(vcpu, gpa, info1);
		}
		else
		{
			if (!npt::g_npt.identity_fault(gpa))
				hv_log("NPF GPA=%llx info1=%llx (map failed)", gpa, info1);
			vcpu->vmcb->ctrl.tlb_control = amd::tlb_flush_asid;
			vcpu->vmcb->ctrl.vmcb_clean = 0;
		}
		nt::ke_release_spin_lock(&npt::g_npt.m_lock, irql);
	}
}

extern "C" std::uint8_t hv_handle_vmexit(hv::vcpu_t* vcpu)
{
	vcpu->vmcb->ctrl.tlb_control = amd::tlb_flush_nothing;
	const std::uint64_t code = vcpu->vmcb->ctrl.exit_code;

	switch (code)
	{
	case amd::vmexit_cpuid:
		hv::handle_cpuid(vcpu);
		break;
	case amd::vmexit_msr:
		hv::handle_msr(vcpu);
		break;
	case amd::vmexit_npf:
		hv::handle_npf(vcpu);
		break;
	case amd::vmexit_db:
		if (!split::handle_db(vcpu))
		{
			// SVM Architecture Reference (33047) §2.16 EVENTINJ matches EXITINTINFO:
			// VECTOR bits 7:0, TYPE bits 10:8 (3 = exception), V bit 31.
			// Vector 1 is #DB — re-inject a guest debug exception we did not consume.
			vcpu->vmcb->ctrl.event_inj = (1ull << 31) | (3ull << 8) | 1;
		}
		break;
	case amd::vmexit_vmmcall:
		vcpu->vmcb->state.rax = vcpu->guest_rcx == 1 ? 0x4856 : static_cast<std::uint64_t>(-1);
		hv::advance_rip(vcpu);
		break;
	case amd::vmexit_vmrun:
	case amd::vmexit_vmload:
	case amd::vmexit_vmsave:
	case amd::vmexit_stgi:
	case amd::vmexit_clgi:
	case amd::vmexit_skinit:
		hv::advance_rip(vcpu);
		break;
	case amd::vmexit_shutdown:
		hv_log("CPU %u shutdown intercept", vcpu->cpu_index);
		break;
	case amd::vmexit_invalid:
		hv_log("CPU %u INVALID VMCB rip=%llx", vcpu->cpu_index, vcpu->vmcb->state.rip);
		for (;;)
			_mm_pause();
	default:
		hv_log("CPU %u unhandled exit %llx rip=%llx", vcpu->cpu_index, code, vcpu->vmcb->state.rip);
		break;
	}

	return 1;
}
