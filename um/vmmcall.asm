.CODE

PUBLIC hv_vmmcall
hv_vmmcall PROC
    push    r8
    mov     rax, rcx
    mov     rcx, rdx
    vmmcall
    pop     r8
    test    r8, r8
    jz      no_aux
    mov     [r8], rdx
no_aux:
    ret
hv_vmmcall ENDP

END
