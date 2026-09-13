#pragma once

#include <stddef.h>

namespace amd
{
	// APM Vol. 2 (24593) CPUID Fn8000_0001_ECX[SVM]: SVM is advertised in ECX bit 2.
	inline constexpr std::uint32_t cpuid_svm = 1u << 2;
	// APM Vol. 2 (24593) CPUID Fn8000_000A_EDX[NP]: nested paging is EDX bit 0 of the SVM feature leaf.
	inline constexpr std::uint32_t cpuid_npt = 1u << 0;
	// CPUID.1.ECX[31] hypervisor-present bit (industry convention, not an AMD SVM field).
	inline constexpr std::uint32_t cpuid_hypervisor = 1u << 31;

	inline constexpr std::uint32_t msr_efer = 0xC0000080;
	inline constexpr std::uint32_t msr_star = 0xC0000081;
	inline constexpr std::uint32_t msr_lstar = 0xC0000082;
	inline constexpr std::uint32_t msr_cstar = 0xC0000083;
	inline constexpr std::uint32_t msr_sfmask = 0xC0000084;
	inline constexpr std::uint32_t msr_fs_base = 0xC0000100;
	inline constexpr std::uint32_t msr_gs_base = 0xC0000101;
	inline constexpr std::uint32_t msr_kernel_gs_base = 0xC0000102;
	inline constexpr std::uint32_t msr_vm_cr = 0xC0010114;
	inline constexpr std::uint32_t msr_vm_hsave_pa = 0xC0010117;
	inline constexpr std::uint32_t msr_sysenter_cs = 0x174;
	inline constexpr std::uint32_t msr_sysenter_esp = 0x175;
	inline constexpr std::uint32_t msr_sysenter_eip = 0x176;
	inline constexpr std::uint32_t msr_pat = 0x277;
	inline constexpr std::uint32_t msr_dbgctl = 0x1D9;

	// APM Vol. 2 (24593) §3.1.7:
	// "Secure Virtual Machine Enable (SVME) Bit. Bit 12, read/write. Enables the SVM
	// extensions. When this bit is zero, the SVM instructions cause #UD exceptions."
	inline constexpr std::uint64_t efer_svme = 1ull << 12;
	// APM Vol. 2 (24593) §15.30.1 VM_CR (C001_0114h): SVMDIS (bit 4) locks EFER.SVME off.
	inline constexpr std::uint64_t vm_cr_svmdis = 1ull << 4;
	// APM Vol. 2 (24593) §3.1.6:
	// "Trap Flag (TF) Bit. Bit 8. Software sets the TF bit to 1 to enable single-step mode
	// during software debug. [...] a debug exception (#DB) occurs immediately after the
	// instruction completes execution."
	inline constexpr std::uint64_t rflags_tf = 1ull << 8;
	inline constexpr std::uint64_t rflags_if = 1ull << 9;

	// VMCB intercepts at control +010h / +014h (APM Vol. 2 Appendix B VMCB layout).
	// +010h bit 18 CPUID, bit 28 MSR_PROT, bit 31 SHUTDOWN.
	inline constexpr std::uint32_t intercept_cpuid = 1u << 18;
	inline constexpr std::uint32_t intercept_msr = 1u << 28;
	inline constexpr std::uint32_t intercept_shutdown = 1u << 31;
	// +014h: bit 0 VMRUN, 1 VMMCALL, 2 VMLOAD, 3 VMSAVE, 4 STGI, 5 CLGI, 6 SKINIT.
	inline constexpr std::uint32_t intercept_vmrun = 1u << 0;
	inline constexpr std::uint32_t intercept_vmmcall = 1u << 1;
	inline constexpr std::uint32_t intercept_vmload = 1u << 2;
	inline constexpr std::uint32_t intercept_vmsave = 1u << 3;
	inline constexpr std::uint32_t intercept_stgi = 1u << 4;
	inline constexpr std::uint32_t intercept_clgi = 1u << 5;
	inline constexpr std::uint32_t intercept_skinit = 1u << 6;
	// Exception intercept bitmap: one bit per vector. Vector 1 is #DB.
	inline constexpr std::uint32_t intercept_db = 1u << 1;

	// APM Vol. 2 (24593) Table 15-9 TLB_CONTROL (undefined encodings are reserved):
	// 00h do nothing, 01h flush entire TLB, 03h flush this guest ASID.
	inline constexpr std::uint8_t tlb_flush_nothing = 0;
	inline constexpr std::uint8_t tlb_flush_all = 1;
	inline constexpr std::uint8_t tlb_flush_asid = 3;
	// APM Vol. 2 (24593) §15.25: nested paging is enabled by NP_ENABLE bit 0 of VMCB +090h.
	inline constexpr std::uint64_t np_enable = 1ull << 0;

	inline constexpr std::uint64_t vmexit_cpuid = 0x72;
	inline constexpr std::uint64_t vmexit_msr = 0x7C;
	inline constexpr std::uint64_t vmexit_shutdown = 0x7F;
	inline constexpr std::uint64_t vmexit_vmrun = 0x80;
	inline constexpr std::uint64_t vmexit_vmmcall = 0x81;
	inline constexpr std::uint64_t vmexit_vmload = 0x82;
	inline constexpr std::uint64_t vmexit_vmsave = 0x83;
	inline constexpr std::uint64_t vmexit_stgi = 0x84;
	inline constexpr std::uint64_t vmexit_clgi = 0x85;
	inline constexpr std::uint64_t vmexit_skinit = 0x86;
	inline constexpr std::uint64_t vmexit_db = 0x41;
	inline constexpr std::uint64_t vmexit_npf = 0x400;
	inline constexpr std::uint64_t vmexit_invalid = ~0ull;

	// APM Vol. 2 (24593) §15.25.6: #NPF EXITINFO1 uses the page-fault error-code layout
	// from §8.4.2, and EXITINFO2 holds the faulting guest-physical address.
	// §8.4.2: "P—Bit 0. If this bit is cleared to 0, the page fault was caused by a
	// not-present page."
	inline constexpr std::uint64_t npf_present = 1ull << 0;
	// §8.4.2: "R/W—Bit 1. [...] If this bit is set to 1, the memory access that caused
	// the page fault was a write."
	inline constexpr std::uint64_t npf_write = 1ull << 1;
	// §8.4.2: "I/D—Bit 4. If this bit is set to 1, it indicates that the access that
	// caused the page fault was an instruction fetch."
	inline constexpr std::uint64_t npf_ifetch = 1ull << 4;

	// Nested PTEs use the long-mode PTE format (APM Vol. 2 §15.25 / §5.3–5.4).
	// §5.4.1: "Present (P) Bit. Bit 0. [...] A page-fault exception (#PF) occurs if an
	// attempt is made to access a table or page when the P bit is 0."
	inline constexpr std::uint64_t npt_present = 1ull << 0;
	// §5.4.1: "Read/Write (R/W) Bit. Bit 1. [...] When the R/W bit is set to 1, both
	// read and write access is allowed."
	inline constexpr std::uint64_t npt_write = 1ull << 1;
	// §5.4.1: "User/Supervisor (U/S) Bit. Bit 2." Nested walks ignore U/S for host
	// privilege; still program it so the entry matches a conventional present PTE.
	inline constexpr std::uint64_t npt_user = 1ull << 2;
	// §5.3.4: PDE.PS selects a 2-Mbyte page (bit 7). Bits 20:0 of the GPA are then
	// the page offset; there is no 4K PT level.
	inline constexpr std::uint64_t npt_large = 1ull << 7;
	// §5.4.1 / §5.6.3: "No Execute (NX) Bit. Bit 63. [...] When the NX bit is set to 1,
	// code cannot be executed from the mapped physical pages."
	// AMD NPT has no execute-only permission: P implies readable; NX is the only
	// execute control. That is why split hooks start with P=0 and use EXITINFO1.I.
	inline constexpr std::uint64_t npt_nx = 1ull << 63;
	inline constexpr std::uint64_t npt_rwx = npt_present | npt_write | npt_user;

#pragma pack(push, 1)
	struct vmcb_segment_t
	{
		std::uint16_t selector;
		std::uint16_t attrib;
		std::uint32_t limit;
		std::uint64_t base;
	};

	struct vmcb_ctrl_t
	{
		std::uint16_t intercept_cr_read;
		std::uint16_t intercept_cr_write;
		std::uint16_t intercept_dr_read;
		std::uint16_t intercept_dr_write;
		std::uint32_t intercept_exception;
		std::uint32_t intercept_misc1;
		std::uint32_t intercept_misc2;
		std::uint8_t reserved_014[0x3C - 0x14];
		std::uint16_t pause_filter_threshold;
		std::uint16_t pause_filter_count;
		std::uint64_t iopm_base_pa;
		std::uint64_t msrpm_base_pa;
		std::uint64_t tsc_offset;
		std::uint32_t guest_asid;
		std::uint8_t tlb_control;
		std::uint8_t reserved_05d[3];
		std::uint64_t v_intr;
		std::uint64_t interrupt_shadow;
		std::uint64_t exit_code;
		std::uint64_t exit_info1;
		std::uint64_t exit_info2;
		std::uint64_t exit_int_info;
		std::uint64_t np_enable;
		std::uint64_t avic_apic_bar;
		std::uint64_t guest_pa_of_ghcb;
		std::uint64_t event_inj;
		std::uint64_t n_cr3;
		std::uint64_t lbr_virtualization;
		std::uint32_t vmcb_clean;
		std::uint32_t reserved_0c4;
		std::uint64_t nrip;
		std::uint8_t inst_fetched_count;
		std::uint8_t inst_bytes[15];
		std::uint8_t reserved_0d0[0x400 - 0x0E0];
	};

	struct vmcb_state_t
	{
		vmcb_segment_t es;
		vmcb_segment_t cs;
		vmcb_segment_t ss;
		vmcb_segment_t ds;
		vmcb_segment_t fs;
		vmcb_segment_t gs;
		vmcb_segment_t gdtr;
		vmcb_segment_t ldtr;
		vmcb_segment_t idtr;
		vmcb_segment_t tr;
		std::uint8_t reserved_0a0[0xCB - 0xA0];
		std::uint8_t cpl;
		std::uint8_t reserved_0cc[4];
		std::uint64_t efer;
		std::uint8_t reserved_0d8[0x148 - 0xD8];
		std::uint64_t cr4;
		std::uint64_t cr3;
		std::uint64_t cr0;
		std::uint64_t dr7;
		std::uint64_t dr6;
		std::uint64_t rflags;
		std::uint64_t rip;
		std::uint8_t reserved_180[0x1D8 - 0x180];
		std::uint64_t rsp;
		std::uint8_t reserved_1e0[0x1F8 - 0x1E0];
		std::uint64_t rax;
		std::uint64_t star;
		std::uint64_t lstar;
		std::uint64_t cstar;
		std::uint64_t sfmask;
		std::uint64_t kernel_gs_base;
		std::uint64_t sysenter_cs;
		std::uint64_t sysenter_esp;
		std::uint64_t sysenter_eip;
		std::uint64_t cr2;
		std::uint8_t reserved_248[0x268 - 0x248];
		std::uint64_t pat;
		std::uint64_t dbgctl;
		std::uint8_t reserved_278[0xC00 - 0x278];
	};

	struct vmcb_t
	{
		vmcb_ctrl_t ctrl;
		vmcb_state_t state;
	};
#pragma pack(pop)

	static_assert(sizeof(vmcb_ctrl_t) == 0x400);
	static_assert(sizeof(vmcb_state_t) == 0xC00);
	static_assert(sizeof(vmcb_t) == 0x1000);
	static_assert(offsetof(vmcb_t, state) == 0x400);
	static_assert(offsetof(vmcb_ctrl_t, exit_code) == 0x70);
	static_assert(offsetof(vmcb_ctrl_t, np_enable) == 0x90);
	static_assert(offsetof(vmcb_ctrl_t, n_cr3) == 0xB0);
	static_assert(offsetof(vmcb_state_t, rip) == 0x178);
	static_assert(offsetof(vmcb_state_t, rsp) == 0x1D8);
	static_assert(offsetof(vmcb_state_t, rax) == 0x1F8);
}

extern "C" std::uint16_t hv_read_cs();
extern "C" std::uint16_t hv_read_ss();
extern "C" std::uint16_t hv_read_ds();
extern "C" std::uint16_t hv_read_es();
extern "C" std::uint16_t hv_read_fs();
extern "C" std::uint16_t hv_read_gs();
extern "C" std::uint16_t hv_read_tr();
extern "C" std::uint16_t hv_read_ldtr();
extern "C" void hv_sgdt(void* dtr);
extern "C" void hv_sidt(void* dtr);
extern "C" std::uint64_t hv_read_rflags();
extern "C" void hv_run_with_nt(void (*fn)(void*), void* arg);
