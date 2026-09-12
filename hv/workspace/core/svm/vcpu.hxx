#pragma once

namespace hv
{
	struct vcpu_t
	{
		std::uint64_t guest_rcx;
		std::uint64_t guest_rdx;
		std::uint64_t guest_rbx;
		std::uint64_t guest_rbp;
		std::uint64_t guest_rsi;
		std::uint64_t guest_rdi;
		std::uint64_t guest_r8;
		std::uint64_t guest_r9;
		std::uint64_t guest_r10;
		std::uint64_t guest_r11;
		std::uint64_t guest_r12;
		std::uint64_t guest_r13;
		std::uint64_t guest_r14;
		std::uint64_t guest_r15;
		std::uint64_t vmcb_pa;
		std::uint64_t host_stack_top;

		amd::vmcb_t* vmcb;
		void* host_stack;
		void* host_save;
		std::uint64_t host_fs_base;
		std::uint64_t host_gs_base;
		std::uint64_t host_kernel_gs_base;
		std::uint64_t host_cr8;
		std::uint64_t guest_cr8;
		std::uint32_t cpu_index;
		bool virtualized;
		bool stop;
		bool single_step;
	};

	static_assert(offsetof(vcpu_t, guest_rcx) == 0);
	static_assert(offsetof(vcpu_t, vmcb_pa) == 112);
	static_assert(offsetof(vcpu_t, host_stack_top) == 120);
	static_assert(offsetof(vcpu_t, vmcb) == 128);
	static_assert(offsetof(vcpu_t, host_fs_base) == 152);
	static_assert(offsetof(vcpu_t, host_gs_base) == 160);
	static_assert(offsetof(vcpu_t, host_kernel_gs_base) == 168);
	static_assert(offsetof(vcpu_t, host_cr8) == 176);
	static_assert(offsetof(vcpu_t, guest_cr8) == 184);

	inline void advance_rip(vcpu_t* vcpu)
	{
		auto& ctrl = vcpu->vmcb->ctrl;
		auto& state = vcpu->vmcb->state;
		if (ctrl.nrip && ctrl.nrip != state.rip)
			state.rip = ctrl.nrip;
		else if (ctrl.inst_fetched_count)
			state.rip += ctrl.inst_fetched_count;
	}

	struct shared_t
	{
		vcpu_t* vcpus;
		std::uint32_t cpu_count;
		void* msrpm;
		void* iopm;
	};

	shared_t g_shared;

	inline void cpuid_text(char* dst, int a, int b, int c)
	{
		crt::memcpy(dst + 0, &a, 4);
		crt::memcpy(dst + 4, &b, 4);
		crt::memcpy(dst + 8, &c, 4);
		dst[12] = 0;
	}

	inline NTSTATUS probe_svm_npt()
	{
		int regs[4]{};
		__cpuid(regs, 0);
		char vendor[13]{};
		cpuid_text(vendor, regs[1], regs[3], regs[2]);
		hv_log("CPUID vendor=%s", vendor);

		__cpuid(regs, 1);
		const bool hypervisor_present = (static_cast<std::uint32_t>(regs[2]) & amd::cpuid_hypervisor) != 0;
		if (hypervisor_present)
		{
			__cpuid(regs, 0x40000000);
			char hv_vendor[13]{};
			cpuid_text(hv_vendor, regs[1], regs[2], regs[3]);
			hv_log("outer hypervisor=%s (SVM is owned by it)", hv_vendor);
			hv_log("disable Hyper-V/VBS: bcdedit /set hypervisorlaunchtype off, then reboot");
		}

		if (crt::strcmp(vendor, "AuthenticAMD") != 0)
		{
			hv_log("this hypervisor is AMD SVM only");
			return STATUS_NOT_SUPPORTED;
		}

		__cpuid(regs, static_cast<int>(0x80000000));
		const auto max_ext = static_cast<std::uint32_t>(regs[0]);
		hv_log("CPUID max_ext=%08x", max_ext);
		if (max_ext < 0x80000001)
		{
			hv_log("extended CPUID too small for SVM");
			return STATUS_NOT_SUPPORTED;
		}

		__cpuid(regs, static_cast<int>(0x80000001));
		const auto ecx = static_cast<std::uint32_t>(regs[2]);
		hv_log("CPUID 80000001 ecx=%08x SVM=%u", ecx, (ecx & amd::cpuid_svm) != 0);
		if ((ecx & amd::cpuid_svm) == 0)
		{
			hv_log("SVM not advertised (BIOS: enable SVM/AMD-V, or another hypervisor is hiding it)");
			return STATUS_NOT_SUPPORTED;
		}

		const std::uint64_t vm_cr = __readmsr(amd::msr_vm_cr);
		hv_log("VM_CR=%llx SVMDIS=%u", vm_cr, (vm_cr & amd::vm_cr_svmdis) != 0);
		if (vm_cr & amd::vm_cr_svmdis)
		{
			hv_log("SVM locked off in VM_CR (firmware/Hyper-V)");
			return STATUS_NOT_SUPPORTED;
		}

		if (max_ext < 0x8000000A)
		{
			hv_log("CPUID 8000000A missing; NPT cannot be confirmed");
			return STATUS_NOT_SUPPORTED;
		}

		__cpuid(regs, static_cast<int>(0x8000000A));
		const auto edx = static_cast<std::uint32_t>(regs[3]);
		hv_log("CPUID 8000000A eax=%08x nasid=%u edx=%08x NP=%u",
			static_cast<std::uint32_t>(regs[0]),
			static_cast<std::uint32_t>(regs[1]),
			edx,
			(edx & amd::cpuid_npt) != 0);
		if ((edx & amd::cpuid_npt) == 0)
		{
			hv_log("nested paging not advertised");
			return STATUS_NOT_SUPPORTED;
		}

		return STATUS_SUCCESS;
	}

	inline bool enable_svm()
	{
		// SVM Architecture Reference (33047) §2.1:
		// "Before any SVM instruction (VMRUN, VMLOAD, VMSAVE, VMMCALL, STGI, CLGI,
		// SKINIT, INVLPGA) can be used, EFER.SVME (bit 12 of the EFER MSR register)
		// must be set to 1."
		const std::uint64_t efer = __readmsr(amd::msr_efer);
		__writemsr(amd::msr_efer, efer | amd::efer_svme);
		return (__readmsr(amd::msr_efer) & amd::efer_svme) != 0;
	}

#pragma pack(push, 1)
	struct dtr_t
	{
		std::uint16_t limit;
		std::uint64_t base;
	};

	struct gdt_entry_t
	{
		std::uint16_t limit_low;
		std::uint16_t base_low;
		std::uint8_t base_mid;
		std::uint8_t access;
		std::uint8_t granularity;
		std::uint8_t base_high;
	};
#pragma pack(pop)

	inline std::uint16_t attrib_from_selector(std::uint16_t selector, std::uint64_t gdt_base, std::uint16_t gdt_limit)
	{
		// Null selector: index and TI are zero; RPL in bits 1:0 may be non-zero.
		if ((selector & ~0x3) == 0)
			return 0;

		const std::uint32_t offset = selector & ~0x7;
		if (offset + sizeof(gdt_entry_t) - 1 > gdt_limit)
			return 0;

		const auto* const entry = reinterpret_cast<gdt_entry_t*>(gdt_base + offset);
		// APM Vol. 2 Appendix B: VMCB segment ATTRIB bits 11:0 are descriptor bits
		// 55:52 concatenated with bits 47:40. That is the access byte plus the high
		// nibble of the granularity byte (G, D/B, L, AVL) shifted into bits 11:8.
		return static_cast<std::uint16_t>(entry->access | ((entry->granularity & 0xF0) << 4));
	}

	inline std::uint64_t base_from_selector(std::uint16_t selector, std::uint64_t gdt_base, std::uint16_t gdt_limit)
	{
		if ((selector & ~0x3) == 0)
			return 0;

		const std::uint32_t offset = selector & ~0x7;
		if (offset + sizeof(gdt_entry_t) - 1 > gdt_limit)
			return 0;

		const auto* const entry = reinterpret_cast<gdt_entry_t*>(gdt_base + offset);
		std::uint64_t base = entry->base_low | (static_cast<std::uint64_t>(entry->base_mid) << 16) |
			(static_cast<std::uint64_t>(entry->base_high) << 24);

		// Access bit 4 is S: 0 = system descriptor. Long-mode system descriptors are
		// 16 bytes; the upper 32 bits of the base live in the second qword.
		if ((entry->access & 0x10) == 0)
		{
			const auto* const high = reinterpret_cast<const std::uint64_t*>(entry) + 1;
			base |= (*high & 0xFFFFFFFFULL) << 32;
		}
		return base;
	}

	inline std::uint32_t limit_from_selector(std::uint16_t selector, std::uint64_t gdt_base, std::uint16_t gdt_limit)
	{
		if ((selector & ~0x3) == 0)
			return 0;

		const std::uint32_t offset = selector & ~0x7;
		if (offset + sizeof(gdt_entry_t) - 1 > gdt_limit)
			return 0;

		const auto* const entry = reinterpret_cast<gdt_entry_t*>(gdt_base + offset);
		std::uint32_t limit = entry->limit_low | (static_cast<std::uint32_t>(entry->granularity & 0x0F) << 16);
		// APM Vol. 2 (24593) §4.7.1:
		// "Granularity (G) Bit. Bit 23 of the upper doubleword. [...] Setting the G
		// bit to 1 indicates that the limit field is scaled by 4 Kbytes (4096 bytes)."
		// Scaled limit = (raw_limit << 12) | 0xFFF so bits 11:0 become ones.
		if (entry->granularity & 0x80)
			limit = (limit << 12) | 0xFFF;
		return limit;
	}

	inline void fill_segment(amd::vmcb_segment_t& seg, std::uint16_t selector, std::uint64_t gdt_base, std::uint16_t gdt_limit)
	{
		seg.selector = selector;
		seg.attrib = attrib_from_selector(selector, gdt_base, gdt_limit);
		seg.limit = limit_from_selector(selector, gdt_base, gdt_limit);
		seg.base = base_from_selector(selector, gdt_base, gdt_limit);
	}

	inline void msrpm_intercept(std::uint8_t* msrpm, std::uint32_t msr)
	{
		// SVM Architecture Reference (33047) Table 2-2 / APM Vol. 2 Table 15-8:
		//   000h  MSRs 0000_0000h–0000_1FFFh
		//   800h  MSRs C000_0000h–C000_1FFFh
		//  1000h  MSRs C001_0000h–C001_1FFFh
		// "For each MSR mapped by the table, two bits are allocated—the lower order
		// of the two bits controls read access to the MSR, and the higher order of
		// the two bits controls write access. A bit value of 1 indicates that the
		// operation is intercepted."
		std::uint32_t range_base = 0;
		std::uint32_t index = 0;
		if (msr <= 0x1FFF)
		{
			range_base = 0;
			index = msr;
		}
		else if (msr >= 0xC0000000 && msr <= 0xC0001FFF)
		{
			range_base = 0x800;
			index = msr - 0xC0000000;
		}
		else if (msr >= 0xC0010000 && msr <= 0xC0011FFF)
		{
			range_base = 0x1000;
			index = msr - 0xC0010000;
		}
		else
		{
			return;
		}

		const std::uint32_t bit = index * 2;
		msrpm[range_base + (bit / 8)] |= static_cast<std::uint8_t>(1u << (bit % 8));
		msrpm[range_base + ((bit + 1) / 8)] |= static_cast<std::uint8_t>(1u << ((bit + 1) % 8));
	}

	inline void capture(vcpu_t* vcpu)
	{
		amd::vmcb_state_t& s = vcpu->vmcb->state;

		dtr_t gdtr{};
		dtr_t idtr{};
		hv_sgdt(&gdtr);
		hv_sidt(&idtr);

		s.gdtr.base = gdtr.base;
		s.gdtr.limit = gdtr.limit;
		s.idtr.base = idtr.base;
		s.idtr.limit = idtr.limit;

		fill_segment(s.es, hv_read_es(), gdtr.base, gdtr.limit);
		fill_segment(s.cs, hv_read_cs(), gdtr.base, gdtr.limit);
		fill_segment(s.ss, hv_read_ss(), gdtr.base, gdtr.limit);
		fill_segment(s.ds, hv_read_ds(), gdtr.base, gdtr.limit);
		fill_segment(s.fs, hv_read_fs(), gdtr.base, gdtr.limit);
		fill_segment(s.gs, hv_read_gs(), gdtr.base, gdtr.limit);
		fill_segment(s.tr, hv_read_tr(), gdtr.base, gdtr.limit);
		fill_segment(s.ldtr, hv_read_ldtr(), gdtr.base, gdtr.limit);

		s.fs.base = __readmsr(amd::msr_fs_base);
		s.gs.base = __readmsr(amd::msr_gs_base);
		s.cpl = 0;
		// Guest EFER must keep SVME; clearing it while running is undefined (APM §3.1.7).
		s.efer = __readmsr(amd::msr_efer) | amd::efer_svme;
		s.cr0 = __readcr0();
		s.cr2 = __readcr2();
		s.cr3 = __readcr3();
		s.cr4 = __readcr4();
		s.dr6 = __readdr(6);
		s.dr7 = __readdr(7);
		s.rflags = hv_read_rflags();
		s.star = __readmsr(amd::msr_star);
		s.lstar = __readmsr(amd::msr_lstar);
		s.cstar = __readmsr(amd::msr_cstar);
		s.sfmask = __readmsr(amd::msr_sfmask);
		s.kernel_gs_base = __readmsr(amd::msr_kernel_gs_base);
		s.sysenter_cs = __readmsr(amd::msr_sysenter_cs);
		s.sysenter_esp = __readmsr(amd::msr_sysenter_esp);
		s.sysenter_eip = __readmsr(amd::msr_sysenter_eip);
		s.pat = __readmsr(amd::msr_pat);
		s.dbgctl = __readmsr(amd::msr_dbgctl);
	}

	inline void setup_ctrl(vcpu_t* vcpu)
	{
		amd::vmcb_ctrl_t& c = vcpu->vmcb->ctrl;
		nt::zero_memory(&c, sizeof(c));

		c.intercept_misc1 = amd::intercept_cpuid | amd::intercept_msr | amd::intercept_shutdown;
		c.intercept_misc2 = amd::intercept_vmrun | amd::intercept_vmmcall | amd::intercept_vmload |
			amd::intercept_vmsave | amd::intercept_stgi | amd::intercept_clgi | amd::intercept_skinit;
		c.intercept_exception = amd::intercept_db;

		c.iopm_base_pa = nt::pa(g_shared.iopm);
		c.msrpm_base_pa = nt::pa(g_shared.msrpm);
		// APM Vol. 2 (24593) §15.16: guest ASID must be non-zero; 0 is reserved for the host.
		c.guest_asid = vcpu->cpu_index + 1;
		c.tlb_control = amd::tlb_flush_all;
		c.np_enable = amd::np_enable;
		c.n_cr3 = npt::g_npt.ncr3();
		c.vmcb_clean = 0;
	}

	extern "C" std::uint8_t hv_svm_launch(vcpu_t* vcpu);

	inline NTSTATUS virtualize_cpu(vcpu_t* vcpu)
	{
		vcpu->vmcb = static_cast<amd::vmcb_t*>(nt::alloc_contig(sizeof(amd::vmcb_t)));
		vcpu->host_save = nt::alloc_contig(page_4kb_size);
		vcpu->host_stack = nt::alloc_contig(host_stack_size);
		if (!vcpu->vmcb || !vcpu->host_save || !vcpu->host_stack)
			return STATUS_INSUFFICIENT_RESOURCES;

		vcpu->vmcb_pa = nt::pa(vcpu->vmcb);
		vcpu->host_stack_top = reinterpret_cast<std::uint64_t>(vcpu->host_stack) + host_stack_size;

		if (!enable_svm())
			return STATUS_UNSUCCESSFUL;

		// SVM Architecture Reference (33047) §2.2.1: "VMRUN saves at least the
		// following host state information at the physical address specified in the
		// new MSR, VM_HSAVE_PA"
		__writemsr(amd::msr_vm_hsave_pa, nt::pa(vcpu->host_save));
		vcpu->host_fs_base = __readmsr(amd::msr_fs_base);
		vcpu->host_gs_base = __readmsr(amd::msr_gs_base);
		vcpu->host_kernel_gs_base = __readmsr(amd::msr_kernel_gs_base);
		vcpu->host_cr8 = __readcr8();
		vcpu->guest_cr8 = vcpu->host_cr8;
		capture(vcpu);
		setup_ctrl(vcpu);

		hv_log("CPU %u VMRUN vmcb=%llx nCR3=%llx", vcpu->cpu_index, vcpu->vmcb_pa, vcpu->vmcb->ctrl.n_cr3);

		if (!hv_svm_launch(vcpu))
		{
			hv_log("CPU %u hv_svm_launch failed", vcpu->cpu_index);
			return STATUS_UNSUCCESSFUL;
		}

		vcpu->virtualized = true;
		hv_log("CPU %u is running as guest", vcpu->cpu_index);
		return STATUS_SUCCESS;
	}

	inline NTSTATUS shared_setup()
	{
		g_shared.msrpm = nt::alloc_contig(msrpm_size);
		g_shared.iopm = nt::alloc_contig(iopm_size);
		if (!g_shared.msrpm || !g_shared.iopm)
			return STATUS_INSUFFICIENT_RESOURCES;

		auto* const msrpm = static_cast<std::uint8_t*>(g_shared.msrpm);
		msrpm_intercept(msrpm, amd::msr_efer);
		msrpm_intercept(msrpm, amd::msr_vm_cr);
		msrpm_intercept(msrpm, amd::msr_vm_hsave_pa);
		return STATUS_SUCCESS;
	}

	inline void shared_teardown()
	{
		nt::free_contig(g_shared.msrpm);
		nt::free_contig(g_shared.iopm);
		g_shared.msrpm = nullptr;
		g_shared.iopm = nullptr;
	}
}
