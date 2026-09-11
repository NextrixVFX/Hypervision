#pragma once

namespace hv
{
	inline const std::uint8_t lab_exec[] = { 0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3 };

	__declspec(noinline) int lab_add(int a, int b)
	{
		return a + b;
	}

	inline void virtualize_this_cpu()
	{
		const ULONG index = nt::ke_get_current_processor_number_ex(nullptr);
		vcpu_t* const vcpu = &g_shared.vcpus[index];
		vcpu->cpu_index = index;

		const NTSTATUS status = virtualize_cpu(vcpu);
		if (!NT_SUCCESS(status))
			hv_log("CPU %u virtualize failed %08x", index, status);
	}

	inline NTSTATUS virtualize_all()
	{
		// Bring-up order is documented in architecture.md (capability check → maps → NPT → split → VMRUN).
		const NTSTATUS caps = probe_svm_npt();
		if (!NT_SUCCESS(caps))
			return caps;

		NTSTATUS status = shared_setup();
		if (!NT_SUCCESS(status))
			return status;

		if (!npt::g_npt.setup())
		{
			shared_teardown();
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		if (!split::install(reinterpret_cast<void*>(&lab_add), lab_exec, sizeof(lab_exec)))
			hv_log("lab split hook failed (continuing without it)");

		g_shared.cpu_count = nt::ke_query_active_processor_count_ex(ALL_PROCESSOR_GROUPS);
		g_shared.vcpus = static_cast<vcpu_t*>(nt::alloc_pool(sizeof(vcpu_t) * g_shared.cpu_count));
		if (!g_shared.vcpus)
		{
			npt::g_npt.cleanup();
			shared_teardown();
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		cpu::run_on_each(virtualize_this_cpu);
		return STATUS_SUCCESS;
	}
}
