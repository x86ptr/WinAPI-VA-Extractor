; HMODULE FASTCALL GetModuleHandle(const char* moduleName)
; FARPROC FASTCALL GetProcAddress(HMODULE hModule, const char* FuncName)

extern GetModuleHandle, GetProcAddress
global main

section .text

main:
    push rbp
    mov rbp, rsp
    ; Write your instructions here
    ;-------------------------------
    ; Example
    ;-------------------------------
    ; retrieves the base address of kernel32.dll
        ; pushes the 'kernel32.dll' on the stack
	xor rdx, rdx
        push rdx ; string null-terminator
        mov rdi, 0x6c6c642e
        push rdi
        mov rdi, 0x32336c656e72656b
        push rdi
        mov rcx, rsp ; moduleName
        call GetModuleHandle ; GetModuleHandle(moduleName) 
    ; retrieves the VA of the WinExec()
        ; pushes the 'WinExec' on the stack
	xor rdx, rdx
        push rdx 
        mov rdi, 0x636578456e6957
        push rdi
        mov rcx, rsp ; FuncName
        mov rdx, rax ; hModule
        call GetProcAddress ; GetProcAddress(FuncName, hModule) 
    ; Calls the WinExec()
        ; pushes the 'calc.exe' on the stack
        xor rdx, rdx
        push rdx 
        mov rdi, 0x6578652e636c6163
        push rdi
        lea rcx, [rsp] ; lpCmdLine
        inc rdx ; uCmdShow
        sub rsp, 0x20
        call rax ; WinExec(lpCmdLine, uCmdShow)
    ;-------------------------------
    leave
    ret
   
