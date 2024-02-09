global GetModuleHandle, GetProcAddress

section .text

GetModuleHandle:
	; rbp - 0x10 (length of module's name)
	; rbp - 0x8  (module's name)
	; return address  
	push rbp
	mov rbp, rsp
	sub rsp, 0x10
	; calculates the length of the module's name
	mov qword [rbp - 0x8], rcx
	call strlen
	mov qword  [rbp - 0x10], rax
	; computes Base Address of module
	push qword  [rbp - 0x8]
	mov rax, gs:[0x60] ; PEB
	mov rax, qword  [rax + 0x18] ; PEB_LDR_DATA
	mov rax, qword  [rax + 0x10] ; LIST_ENTRY InLoadOrderModuleList (process.exe)
	xor rcx, rcx
	push rax
	; counts the number of loaded modules
	GMA_Counter:
		mov rdx, [rax + 0x30]
		cmp rdx, 0x0
		jz GMA_Find
		inc rcx
		mov rax, [rax]
		jmp GMA_Counter 
	; goes to compare and find module
	GMA_Find:
		pop rax
		GMH_Loop:
			mov rdi, qword  [rbp - 0x8]
			lea rsi, qword  [rax + 58h]
			mov rsi, qword  [rsi + 8h]
			push rcx
			mov rcx, qword  [rbp - 0x10]
			dec rcx
			GMA_LowerCase:
				; converts uppercase letters to lowercase letters
				mov bl, 61h
				mov bh, 39h ; scapes the ASCII numbers
				cmp bh, [rsi]
				ja GMH_CMP
				cmp bl, [rsi]
				jna GMH_CMP
				add byte  [rsi], 20h
				GMH_CMP:
					; compares the string with the name of the loaded module
					cmpsb
					jnz GMH_NextModule
					cmp rcx, 0x1
					jz GMH_Found
					inc rsi ; scapes the unicode bytes
					loop GMA_LowerCase
			GMH_NextModule:
				mov rax, [rax]
				pop rcx
				loop GMH_Loop 
				jmp GMH_EndProc
	GMH_Found:
		pop rcx
	GMH_EndProc:
		mov rax, qword  [rax + 0x30] 
		cmp rax, 0x0
		jz GMH_GetError
		jmp GMH_Exit
	GMH_GetError:
		mov rax, 0xFFFFFFFFFFFFFFFF
	GMH_Exit:
		leave
		mov r9, rbp
		sub r9, rsp
		sub r9, 0x8
		pop rcx
		add rsp, r9
		jmp rcx 

GetProcAddress:
	; rbp - 0x48   (VA of target function)
	; rbp - 0x40   (VA of name ordinals)
	; rbp - 0x38   (VA of names)
	; rbp - 0x30   (VA of function)
	; rbp - 0x28   (number of function)
	; rbp - 0x20   (VA of export directory)
	; rbp - 0x18   (length of function's name)
	; rbp - 0x10   (base address of kernel32.dll)
	; rbp - 0x8    (function's name)
	; return address
	push rbp
	mov rbp, rsp
	sub rsp, 48h
	mov qword  [rbp - 0x8], rcx 
	mov qword [rbp - 0x10], rdx
	; calculates the length of the function's name
	call strlen
	mov qword  [rbp - 0x18], rax
	mov rax, qword  [rbp - 0x10] 
	; Export directory
	mov eax, dword [rax + 0x3C]  ; e_lfanew
	add rax, qword  [rbp - 0x10] ; PE signature
	mov eax, dword  [rax + 0x88] ; RVA of Export directory
	add rax, qword  [rbp - 0x10] ; VA of the Export directory
	mov qword  [rbp - 0x20], rax ; stores the VA of the Export directory on the stack
	; NumberOfFunctions
	mov eax, dword  [rax + 14h]
	mov qword [rbp - 0x28], rax
	; AddressOfFunctions
	mov rax, qword  [rbp - 0x20] ; VA of the Export directory    
	mov eax, dword  [rax + 1Ch] 
	add rax, qword  [rbp - 0x10] ; adds with base address
	mov qword  [rbp - 30h], rax    
	; AddressOfNames
	mov rax, qword  [rbp - 0x20] 
	mov eax, dword  [rax + 20h]
	add rax, qword  [rbp - 0x10]   
	mov qword  [rbp - 0x38], rax 
	; AddressOfNameOrdinals
	mov rax, qword  [rbp - 0x20]   
	mov eax, dword  [rax + 24h]         
	add rax, qword  [rbp - 0x10] 
	mov qword  [rbp - 0x40], rax 
	; goes to find the VA of function
	mov rcx, qword  [rbp - 0x28] ; loop counter (number of functions)
	xor rax, rax
	xor rdx, rdx
	mov rbx, 0x4
	GPA_CMPName:
		; at each run it loads the address of each function into the names table in the RSI register
		mov rsi, qword  [rbp - 0x38]
		add rsi, rax
		mov esi, dword  [rsi]
		add rsi, qword  [rbp - 0x10]
		; loads the address of the target fucntion's name into the RDI register
		mov rdi, qword  [rbp - 0x8]
		mov qword  [rbp - 0x28], rcx
		mov rcx, qword  [rbp - 0x18] ; length of module's name
		repe cmpsb ; compare RSI and RDI
		jz GPA_EndProc ; jump is taken if (found or not found)
		mov rcx, qword  [rbp - 0x28]
		add rax, 0x4
		loop GPA_CMPName
	GPA_EndProc:
		mov rcx, qword  [rbp - 0x28]
		cmp rcx, 0x1 ; if the function's name is not found, it will throw an error
		jz GPA_GetError
		div rbx
		; finds the ordinal position of the function
		mov rdx, qword  [rbp - 0x40]    ; AddressOfNameOrdinals
		mov cx, word  [rdx + rax * 0x2] ; NameOrdinal position
		; finds the VA of the function
		mov rdx, qword  [rbp - 30h]       ; AddressOfFunctions
		mov edx, dword  [rdx + rcx * 0x4] ; RVA of function
		add rdx, qword  [rbp - 0x10]      ; VA of function
		mov rax, rdx
		jmp GPA_Exit
		GPA_GetError:
			mov rax, 0xFFFFFFFFFFFFFFFF
		GPA_Exit:
			leave
			mov r9, rbp
			sub r9, rsp
			sub r9, 0x8
			pop rcx
			add rsp, r9
			jmp rcx

; calculates the length of passed string
strlen:
    ; rbp - 0x8	(address of string)	
    ; return address	
    push rbp
    mov rbp, rsp
    sub rsp, 0x8
    cld
    mov qword [rbp - 0x8], rcx
    mov rdi, rcx
    xor rcx, rcx
    mov rcx, 0xFFFFFFFFFFFFFFFF
    xor rax, rax
    repne scasb
    mov rax, [rbp - 0x8]
    sub rdi, rax
    xchg rax, rdi
    leave
    ret