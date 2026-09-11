; Keep offsets in sync with hv::vcpu_t in workspace/core/svm/vcpu.hxx.

PUBLIC hv_svm_launch
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

END
