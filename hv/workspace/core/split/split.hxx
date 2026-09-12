#pragma once

namespace split
{
	struct hook_t
	{
		std::uint64_t gpa;
		std::uint64_t original_pa;
		std::uint64_t execute_pa;
		void* original_va;
		void* execute_va;
		bool used;
	};

	hook_t g_hooks[split_max_hooks];

	inline hook_t* find(std::uint64_t gpa)
	{
		const std::uint64_t page = gpa & ~page_4kb_mask;
		for (auto& hook : g_hooks)
		{
			if (hook.used && hook.gpa == page)
				return &hook;
		}
		return nullptr;
	}

	inline void hide(hook_t& hook)
	{
		std::uint64_t* const pte = npt::g_npt.pte(hook.gpa);
		// APM Vol. 2 (24593) §5.4.1: "When the P bit is 0, indicating a not-present
		// page, all remaining bits in the page data-structure entry are available to
		// software." Clearing P forces #NPF on both fetch and data so we can pick
		// the execute vs original shadow from EXITINFO1.I.
		if (pte)
			*pte &= ~amd::npt_present;
	}

	inline void show(hook_t& hook, std::uint64_t hpa)
	{
		std::uint64_t* const pte = npt::g_npt.pte(hook.gpa);
		if (!pte)
			return;
		*pte = (hpa & ~page_4kb_mask) | amd::npt_rwx;
	}

	inline bool owns(std::uint64_t gpa)
	{
		return find(gpa) != nullptr;
	}

	inline bool owns_2mb(std::uint64_t gpa)
	{
		const std::uint64_t base = gpa & ~page_2mb_mask;
		for (auto& hook : g_hooks)
		{
			if (hook.used && (hook.gpa & ~page_2mb_mask) == base)
				return true;
		}
		return false;
	}

	inline bool install(void* guest_va, const void* exec_bytes, std::size_t length)
	{
		if (!guest_va || !exec_bytes || length == 0 || length > page_4kb_size)
			return false;

		const std::uint64_t page_va = reinterpret_cast<std::uint64_t>(guest_va) & ~page_4kb_mask;
		const std::uint64_t offset = reinterpret_cast<std::uint64_t>(guest_va) & page_4kb_mask;
		if (offset + length > page_4kb_size)
		{
			hv_log("split hook cannot cross a page boundary");
			return false;
		}

		const std::uint64_t gpa = nt::pa(reinterpret_cast<void*>(page_va));
		if (!gpa)
			return false;

		if (find(gpa))
		{
			hv_log("GPA %llx already hooked", gpa);
			return false;
		}

		hook_t* slot = nullptr;
		for (auto& hook : g_hooks)
		{
			if (!hook.used)
			{
				slot = &hook;
				break;
			}
		}
		if (!slot)
			return false;

		void* const original = nt::alloc_contig(page_4kb_size);
		void* const execute = nt::alloc_contig(page_4kb_size);
		if (!original || !execute)
		{
			nt::free_contig(original);
			nt::free_contig(execute);
			return false;
		}

		nt::copy_memory(original, reinterpret_cast<void*>(page_va), page_4kb_size);
		nt::copy_memory(execute, original, page_4kb_size);
		nt::copy_memory(static_cast<std::uint8_t*>(execute) + offset, exec_bytes, length);

		if (!npt::g_npt.split_2mb(gpa))
		{
			nt::free_contig(original);
			nt::free_contig(execute);
			return false;
		}

		slot->gpa = gpa;
		slot->original_va = original;
		slot->execute_va = execute;
		slot->original_pa = nt::pa(original);
		slot->execute_pa = nt::pa(execute);
		slot->used = true;

		hide(*slot);
		hv_log("split hook GPA %llx orig=%llx exec=%llx", gpa, slot->original_pa, slot->execute_pa);
		return true;
	}

	inline void handle_npf(hv::vcpu_t* vcpu, std::uint64_t gpa, std::uint64_t info1)
	{
		hook_t* const hook = find(gpa);
		if (!hook)
			return;

		const bool fetch = (info1 & amd::npf_ifetch) != 0;
		show(*hook, fetch ? hook->execute_pa : hook->original_pa);

		vcpu->single_step = true;
		// APM Vol. 2 (24593) §3.1.6: TF causes #DB after the next instruction so we
		// can hide the page again. Exception intercept bit 1 catches that #DB
		// before it is delivered to Windows.
		vcpu->vmcb->state.rflags |= amd::rflags_tf;
		vcpu->vmcb->ctrl.intercept_exception |= amd::intercept_db;
		vcpu->vmcb->ctrl.tlb_control = amd::tlb_flush_asid;
		vcpu->vmcb->ctrl.vmcb_clean = 0;
	}

	inline bool handle_db(hv::vcpu_t* vcpu)
	{
		if (!vcpu->single_step)
			return false;

		vcpu->single_step = false;
		vcpu->vmcb->state.rflags &= ~amd::rflags_tf;

		for (auto& hook : g_hooks)
		{
			if (hook.used)
				hide(hook);
		}

		vcpu->vmcb->ctrl.tlb_control = amd::tlb_flush_asid;
		vcpu->vmcb->ctrl.vmcb_clean = 0;
		return true;
	}
}
