; Keep offsets in sync with hv::vcpu_t in workspace/core/svm/vcpu.hxx.

PUBLIC hv_svm_launch
PUBLIC hv_run_with_nt
PUBLIC hv_read_cs
PUBLIC hv_read_ss
PUBLIC hv_read_ds
PUBLIC hv_read_es
PUBLIC hv_read_fs
PUBLIC hv_read_gs
PUBLIC hv_read_tr
PUBLIC hv_read_ldtr
PUBLIC hv_sgdt
PUBLIC hv_sidt
PUBLIC hv_read_rflags

EXTERN hv_handle_vmexit:PROC

HV_VCPU_RCX            EQU 0
HV_VCPU_RDX            EQU 8
HV_VCPU_RBX            EQU 16
HV_VCPU_RBP            EQU 24
HV_VCPU_RSI            EQU 32
HV_VCPU_RDI            EQU 40
HV_VCPU_R8             EQU 48
HV_VCPU_R9             EQU 56
HV_VCPU_R10            EQU 64
HV_VCPU_R11            EQU 72
HV_VCPU_R12            EQU 80
HV_VCPU_R13            EQU 88
HV_VCPU_R14            EQU 96
HV_VCPU_R15            EQU 104
HV_VCPU_VMCB_PA        EQU 112
HV_VCPU_HOST_STACK_TOP EQU 120
HV_VCPU_VMCB           EQU 128
HV_VCPU_HOST_FS        EQU 152
HV_VCPU_HOST_GS        EQU 160
HV_VCPU_HOST_KERNEL_GS EQU 168
HV_VCPU_HOST_CR8       EQU 176
HV_VCPU_GUEST_CR8      EQU 184

IA32_FS_BASE           EQU 0C0000100h
IA32_GS_BASE           EQU 0C0000101h
IA32_KERNEL_GS_BASE    EQU 0C0000102h

HV_VMCB_RIP            EQU 0578h
HV_VMCB_RSP            EQU 05D8h

.code

hv_read_cs PROC
    mov ax, cs
    ret
hv_read_cs ENDP

hv_read_ss PROC
    mov ax, ss
    ret
hv_read_ss ENDP

hv_read_ds PROC
    mov ax, ds
    ret
hv_read_ds ENDP

hv_read_es PROC
    mov ax, es
    ret
hv_read_es ENDP

hv_read_fs PROC
    mov ax, fs
    ret
hv_read_fs ENDP

hv_read_gs PROC
    mov ax, gs
    ret
hv_read_gs ENDP

hv_read_tr PROC
    str ax
    ret
hv_read_tr ENDP

hv_read_ldtr PROC
    sldt ax
    ret
hv_read_ldtr ENDP

hv_sgdt PROC
    sgdt [rcx]
    ret
hv_sgdt ENDP

hv_sidt PROC
    sidt [rcx]
    ret
hv_sidt ENDP

hv_read_rflags PROC
    pushfq
    pop rax
    ret
hv_read_rflags ENDP

hv_svm_launch PROC
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov rdx, [rcx + HV_VCPU_VMCB]
    lea rax, guest_land
    mov qword ptr [rdx + HV_VMCB_RIP], rax
    mov qword ptr [rdx + HV_VMCB_RSP], rsp

    ; Host stack is 16-byte aligned; the extra 8 bytes leave shadow space for the
    ; vcpu pointer that the loop reloads after every #VMEXIT.
    mov rsp, [rcx + HV_VCPU_HOST_STACK_TOP]
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 8
    mov [rsp], rcx

host_loop:
    mov rax, [rsp]

    mov rcx, [rax + HV_VCPU_RCX]
    mov rdx, [rax + HV_VCPU_RDX]
    mov rbx, [rax + HV_VCPU_RBX]
    mov rbp, [rax + HV_VCPU_RBP]
    mov rsi, [rax + HV_VCPU_RSI]
    mov rdi, [rax + HV_VCPU_RDI]
    mov r8,  [rax + HV_VCPU_R8]
    mov r9,  [rax + HV_VCPU_R9]
    mov r10, [rax + HV_VCPU_R10]
    mov r11, [rax + HV_VCPU_R11]
    mov r12, [rax + HV_VCPU_R12]
    mov r13, [rax + HV_VCPU_R13]
    mov r14, [rax + HV_VCPU_R14]
    mov r15, [rax + HV_VCPU_R15]
    mov rax, [rax + HV_VCPU_VMCB_PA]

    ; SVM does not switch CR8. Load the guest value before VMRUN so the
    ; guest keeps its IRQL; host CR8 is restored after #VMEXIT.
    push rax
    mov rax, [rsp + 8]
    mov rax, [rax + HV_VCPU_GUEST_CR8]
    and rax, 0Fh
    mov cr8, rax
    pop rax

    ; SVM Architecture Reference (33047) §2.13: clear GIF so the host world-switch
    ; is atomic. VMRUN then sets GIF=1 after guest state is loaded.
    ; §2.11: VMLOAD/VMSAVE take the VMCB physical address in rAX and move hidden
    ; FS/GS/STAR/SYSENTER state that VMRUN itself does not cover.
    ; §2.2.1: "The VMRUN instruction has an implicit addressing mode of [rAX].
    ; Software must load RAX with the physical address of the VMCB, a 4-Kbyte-
    ; aligned page."
    clgi
    vmload rax
    vmrun rax
    vmsave rax

    mov rax, [rsp]
    mov [rax + HV_VCPU_RCX], rcx
    mov [rax + HV_VCPU_RDX], rdx
    mov [rax + HV_VCPU_RBX], rbx
    mov [rax + HV_VCPU_RBP], rbp
    mov [rax + HV_VCPU_RSI], rsi
    mov [rax + HV_VCPU_RDI], rdi
    mov [rax + HV_VCPU_R8], r8
    mov [rax + HV_VCPU_R9], r9
    mov [rax + HV_VCPU_R10], r10
    mov [rax + HV_VCPU_R11], r11
    mov [rax + HV_VCPU_R12], r12
    mov [rax + HV_VCPU_R13], r13
    mov [rax + HV_VCPU_R14], r14
    mov [rax + HV_VCPU_R15], r15

    ; CR8 is guest IRQL at this point. Park it and restore the host value
    ; saved at virtualize so NT sees PASSIVE, not 0xFF from a TEB GS.
    mov r11, cr8
    mov [rax + HV_VCPU_GUEST_CR8], r11
    mov r11, [rax + HV_VCPU_HOST_CR8]
    and r11, 0Fh
    mov cr8, r11

    ; VMRUN/#VMEXIT restore CS/RIP/CR3/IDT from HSAVE, not FS/GS. VMLOAD before
    ; VMRUN loaded guest FS/GS (the TEB when the guest was in CPL3). NT APIs
    ; use GS as KPCR — write the host bases saved at virtualize before C code.
    mov r11, rax
    mov ecx, IA32_FS_BASE
    mov rax, [r11 + HV_VCPU_HOST_FS]
    mov rdx, rax
    shr rdx, 32
    wrmsr
    mov ecx, IA32_GS_BASE
    mov rax, [r11 + HV_VCPU_HOST_GS]
    mov rdx, rax
    shr rdx, 32
    wrmsr
    mov ecx, IA32_KERNEL_GS_BASE
    mov rax, [r11 + HV_VCPU_HOST_KERNEL_GS]
    mov rdx, rax
    shr rdx, 32
    wrmsr
    mov rax, r11

    pushfq
    and qword ptr [rsp], 0FFFFFFFFFFFFFEFFh
    popfq

    ; Stay on host_stack. Do not STGI here — that re-enabled the clock on
    ; every #NPF and caused 0x101. hv_handle_vmexit publishes host_stack in
    ; the current KTHREAD so a nested #PF is not 0x1AA.
    mov rcx, rax
    sub rsp, 20h
    call hv_handle_vmexit
    add rsp, 20h

    test al, al
    jnz host_loop
    jmp host_loop

guest_land:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    mov eax, 1
    ret
hv_svm_launch ENDP

; rcx = fn, rdx = arg
; Already on host_stack. STGI so MmCopyMemory can #PF; CLI so the clock DPC
; does not run here (0xD1 IRQL=0xFF). C code has already bound this stack
; into the current KTHREAD so that #PF is not 0x1AA.
hv_run_with_nt PROC
    push rbx
    push rsi
    mov rbx, rsp
    mov rsi, rcx
    mov rcx, rdx
    pushfq
    and qword ptr [rsp], 0FFFFFFFFFFFFFCFFh
    popfq
    cli
    xor eax, eax
    mov dr7, rax
    sub rsp, 20h
    stgi
    call rsi
    clgi
    add rsp, 20h
    mov rsp, rbx
    pop rsi
    pop rbx
    ret
hv_run_with_nt ENDP

END
