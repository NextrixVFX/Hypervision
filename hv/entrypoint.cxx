#include <impl/includes.hxx>

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT driver,
	_In_ PUNICODE_STRING registry_path)
{
	if (!nt::g_resolver.setup())
		return STATUS_UNSUCCESSFUL;

	if (!nt::resolve_core())
		return STATUS_PROCEDURE_NOT_FOUND;

	gadgets::g_gadgets.setup();
	hv_log("ntoskrnl=%llx gadgets=%u", nt::g_resolver.nt_base(), gadgets::g_gadgets.count());

	const bool mapped = nt::is_manual_map(driver, registry_path);
	if (mapped)
		hv_log("manually mapped hypervision");
	else
		hv_log("windows mapped hypervision");

	hv_log("loading hypervision");

	const NTSTATUS status = hv::virtualize_all();
	if (!NT_SUCCESS(status))
	{
		hv_log("virtualize_all failed %08x", status);
		return status;
	}

	const int sum = hv::lab_add(2, 3);
	hv_log("lab_add(2, 3) = %d (5=original, 4919=execute shadow)", sum);
	return STATUS_SUCCESS;
}

