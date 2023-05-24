; HMODULE stdcall GetModuleHandle(const char* moduleName)
; FARPROC stdcall GetProcAddress(HMODULE hModule, const char* FuncName)

extern GetModuleHandle, GetProcAddress
global main

section .text

main:
    push ebp
    mov ebp, esp
    ; Write your instructions here
    ;-------------------------------
    ; Example
    ;-------------------------------
    ; retrieves the base address of kernel32.dll
    	; pushes the 'kernel32.dll' on the stack
	xor ebx, ebx
	push ebx ; string null-terminator
	push 0x6c6c642e
	push 0x32336c65
	push 0x6e72656b
	push esp ; Module
	call GetModuleHandle ; GetModuleHandle(moduleName) 
    ; retrieves the VA of the WinExec()
	; pushes the 'WinExec' on the stack
	xor ebx, ebx
	push ebx 
	push 0x636578
	push 0x456e6957
	push esp ; Function
	push eax ; hModule
	call GetProcAddress ; GetProcAddress(FuncName, hModule) 
    ; Calls the WinExec()
	xor ebx, ebx
        inc ebx
        push ebx ; uCmdShow
	; pushes the 'calc.exe' on the stack
        xor ebx, ebx
	push ebx
	push 0x6578652e
	push 0x636c6163
	push esp ; lpCmdLine
	call eax ; WinExec(lpCmdLine, uCmdShow)
    ;-------------------------------
    leave
    ret
