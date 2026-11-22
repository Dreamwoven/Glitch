; One-shot x64 EntryPoint bootstrap trampoline.
; Invoked when Windows transfers execution to RiftApart.exe's PE EntryPoint
; (after all static DLL DllMains have finished and OS loader lock is released,
; but BEFORE __security_init_cookie, CRT _initterm, and WinMain!).
;
; Calls ProxyOnHostEntryPoint() which restores the original 14 bytes of the host
; EntryPoint, loads RiftLoader.dll, runs RiftLoader_Initialize(), and returns
; the host EntryPoint address in RAX. We then restore all registers and tail-jump
; straight into the real EntryPoint as if nothing happened.

OPTION CASEMAP:NONE

EXTERN ProxyOnHostEntryPoint:PROC

.CODE

PUBLIC ProxyEntryPointTrampoline
ProxyEntryPointTrampoline PROC
    ; Entry RSP is 16n+8. Subtract 78h -> 16-byte aligned + shadow space + reg save area.
    sub rsp, 78h
    mov [rsp+20h], rcx
    mov [rsp+28h], rdx
    mov [rsp+30h], r8
    mov [rsp+38h], r9
    movaps [rsp+40h], xmm0
    movaps [rsp+50h], xmm1
    movaps [rsp+60h], xmm2

    call ProxyOnHostEntryPoint

    movaps xmm2, [rsp+60h]
    movaps xmm1, [rsp+50h]
    movaps xmm0, [rsp+40h]
    mov r9,  [rsp+38h]
    mov r8,  [rsp+30h]
    mov rdx, [rsp+28h]
    mov rcx, [rsp+20h]
    add rsp, 78h
    jmp rax
ProxyEntryPointTrampoline ENDP

END
