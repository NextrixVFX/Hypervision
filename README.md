# Hypervision

Type-2 AMD SVM hypervisor that loads as a Windows kernel driver. After `VMRUN`, Windows continues as the guest on every logical processor; this driver stays in a per-CPU `VMRUN` loop and uses nested paging (NPT).

It is a lab for SVM + NPT, not a product hypervisor. There is no unload path: reboot to drop SVM.

## Requirements

- Physical **AMD** CPU with AMD-V and nested paging (not Intel VT-x)
- Hyper-V / VBS / WSL2 **off**. If CPUID.1.ECX[31] is set, this Windows instance does not own SVM
- Visual Studio with **WDK** (project targets Windows 10, SDK `10.0.28000.0`, toolset `WindowsKernelModeDriver10.0`)
- **x64** only

Check the firmware SVM / AMD-V switch, then:

```bat
bcdedit /set hypervisorlaunchtype off
bcdedit /set testsigning on
```

Reboot. `systeminfo` should report that a hypervisor is **not** detected.

## Build

Open `Hypervision.slnx` (or `hv/hv.vcxproj`) and build **Debug|x64** or **Release|x64**.

```bat
msbuild hv\hv.vcxproj /p:Configuration=Debug /p:Platform=x64
```

Output: `builds/hv/Hypervision.sys` (empty IAT; ntoskrnl exports are resolved from the PE at runtime).

## Load

Test-signed service (admin):

```bat
sc create hv type= kernel binPath= "C:\path\to\Hypervision.sys"
sc start hv
```

Watch `DbgPrint` (`hv: …`) with WinDbg or DebugView.

`DriverEntry` also accepts a mapped image (null `DRIVER_OBJECT`, MZ at arg0, or second-arg magic `0x1337`) and will not write `DriverUnload`.

On success you should see virtualize logs per CPU, then:

```text
hv: lab_add(2, 3) = 4919 (5=original, 4919=execute shadow)
```

`4919` means the NPT split-page lab replaced `lab_add`’s execute path with `mov eax, 1337h; ret`. `5` means the execute shadow is not active.

If bring-up fails with `c00000bb` (`STATUS_NOT_SUPPORTED`), the probe prints CPU vendor, outer hypervisor name, `SVM`, `VM_CR.SVMDIS`, and NPT bits. Typical cause is Hyper-V still running.

## Layout

```text
Hypervision.slnx
hv/
  entrypoint.cxx              DriverEntry (only C++ TU)
  impl/
    amd/svm.hxx, svm.asm      VMCB, intercepts, VMRUN loop
    nt/                       ntoskrnl base, g_resolver, export wrappers
    gadgets/                  ntoskrnl gadget scan utility
    crt/, std/                no-CRT helpers, PE types
    hv.inf
  workspace/
    core/npt/                 identity NPT (2MB, 4K split)
    core/svm/                 per-CPU virtualize, VMEXIT
    core/split/               split-page lab on lab_add
    utility/
```

Header-only hypervisor logic; MASM for `VMRUN`/`VMLOAD`/`VMSAVE` and `get_nt_base`.

## What it does

1. Resolve ntoskrnl (`get_nt_base` + export walk).
2. Probe SVM + NPT (CPUID `80000001h` / `8000000Ah`, `VM_CR`).
3. Identity-map RAM in NPT (`GPA == SPA`, 2MB leaves).
4. Optional split hook on `lab_add`: hooked GPA starts not present; `#NPF` uses `EXITINFO1.I` to choose execute vs original page, then `RFLAGS.TF` + `#DB` to hide again.
5. Pin each CPU, enable `EFER.SVME`, capture state into a VMCB, `VMRUN`. First entry lands in `guest_land` and returns into Windows as the guest.

Unknown GPAs `#NPF` and are mapped on demand as 2MB identity pages.

AMD manuals used in comments: APM Vol. 2 (24593) and SVM Architecture Reference (33047).

## Limits

- AMD only; will not run under Hyper-V
- Unload is not implemented
- Split-page hooks that single-step are expensive on hot pages (two `#VMEXIT`s per instruction)
- AMD NPT has no execute-only permission (Present implies readable)
