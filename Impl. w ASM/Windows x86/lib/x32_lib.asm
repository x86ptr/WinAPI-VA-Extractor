global GetModuleHandle, GetProcAddress

section .text

GetModuleHandle:
	; rbp - 0x8 (base address of module)
	; rbp - 0x4 (length of module's name)
	; rbp
	; return address
	; rbp + 0x8 (module's name)
	push ebp
	mov ebp, esp
	sub esp, 0x8
	pushad
	; calculates the length of the module's name
	push dword  [ebp + 0x8]
	call strlen
	mov dword  [ebp - 0x4], eax
	; computes Base Address of module
	push dword  [ebp + 0x8]
	mov eax, fs:[0x30] ; PEB
	mov eax, dword  [eax + 0xC]  ; PEB_LDR_DATA
	mov eax, dword  [eax + 0x14] ; LIST_ENTRY InMemoryOrderModuleList (process.exe)
	xor ecx, ecx
	push eax
	; counts the number of loaded modules
	GMA_Counter:
		mov edx, [eax + 0x10]
		cmp edx, 0x0
		jz GMA_Find
		inc ecx
		mov eax, [eax]
		jmp GMA_Counter 
	; goes to compare and find module
	GMA_Find:
		pop eax
		GMH_Loop:
			mov edi, dword  [ebp + 0x8]
			lea esi, dword  [eax + 0x24]
			mov esi, dword  [esi + 0x4]
			push ecx
			mov ecx, dword  [ebp - 0x4]
			dec ecx
			GMA_LowerCase:
				; converts uppercase letters to lowercase letters
				mov bl, 0x61
				mov bh, 0x39 ; scapes the ASCII numbers
				cmp bh, [esi]
				ja GMH_CMP
				cmp bl, [esi]
				jna GMH_CMP
				add byte  [esi], 0x20
				GMH_CMP:
					; compares the string with the name of the loaded module
					cmpsb
					jnz GMH_NextModule
					cmp ecx, 0x1
					jz GMH_Found
					inc esi ; scapes the unicode bytes
					loop GMA_LowerCase
			GMH_NextModule:
				mov eax, [eax]
				pop ecx
				loop GMH_Loop 
				jmp GMH_EndProc
	GMH_Found:
		pop ecx
	GMH_EndProc:
		mov eax, dword  [eax + 0x10] 
		cmp eax, 0x0
		jz GMH_GetError
		jmp GMH_Exit
	GMH_GetError:
		mov eax, 0xFFFFFFFF
	GMH_Exit:
		add esp, 0x4
		mov dword  [ebp - 0x8], eax
		popad
		mov eax, dword  [ebp - 0x8]
		leave
		ret 0x4

GetProcAddress:
	; rbp - 0x1C (VA of target function)
	; rbp - 0x18 (VA of name ordinals)
	; rbp - 0x14 (VA of names)
	; rbp - 0x10 (VA of function)
	; rbp - 0xC  (number of function)
	; rbp - 0x8  (VA of export directory)
	; rbp - 0x4  (length of function's name)
	; rbp
	; return address
	; rbp + 0x8  (base address of kernel32.dll)
	; rbp + 0xC  (function's name)
	push ebp
	mov ebp, esp
	sub esp, 0x1C
	pushad
	; calculates the length of the function name
	push dword  [ebp + 0xC]
	call strlen
	mov dword  [ebp - 0x4], eax
	mov eax, dword  [ebp + 0x8] 
	; Export directory
	mov eax, dword  [eax + 0x3C] ; e_lfanew
	add eax, dword  [ebp + 0x8]  ; PE signature
	mov eax, dword  [eax + 0x78] ; RVA of Export directory
	add eax, dword  [ebp + 0x8]  ; VA of the Export directory
	mov dword  [ebp - 0x8], eax  ; stores the VA of the Export directory on the stack 
	; NumberOfFunctions
	mov eax, dword  [eax + 0x14]
	mov dword  [ebp - 0xC], eax
	; AddressOfFunctions
	mov eax, dword  [ebp - 0x8] ; VA of the Export directory    
	mov eax, dword  [eax + 0x1C] 
	add eax, dword  [ebp + 0x8] ; adds with base address
	mov dword  [ebp - 0x10], eax    
	; AddressOfNames
	mov eax, dword  [ebp - 0x8] 
	mov eax, dword  [eax + 0x20]
	add eax, dword  [ebp + 0x8]    
	mov dword  [ebp - 0x14], eax 
	; AddressOfNameOrdinals
	mov eax, dword  [ebp - 0x8]    
	mov eax, dword  [eax + 0x24]         
	add eax, dword  [ebp + 0x8]
	mov dword  [ebp - 0x18], eax 
	; goes to find VA of function
	mov ecx, dword  [ebp - 0xC] ; loop counter (number of functions)
	xor eax, eax
	xor edx, edx
	mov ebx, 0x4
	GPA_CMPName:
		; at each run it loads the address of each function into the names table in the ESI register
		mov esi, dword  [ebp - 0x14]
		add esi, eax
		mov esi, dword  [esi]
		add esi, dword  [ebp + 0x8]
		; loads the address of the target function name into the EDI register
		mov edi, dword  [ebp + 0xC]
		mov dword  [ebp - 0xC], ecx
		mov ecx, dword  [ebp - 0x4] ; length of module's name
		repe cmpsb ; compare ESI and EDI
		jz GPA_EndProc ; jump is taken if (found or not found)
		mov ecx, dword  [ebp - 0xC]
		add eax, 0x4
		loop GPA_CMPName
	GPA_EndProc:
		mov ecx, dword  [ebp - 0xC]
		cmp ecx, 0x1 ; if the function name is not found, it will throw an error
		jz GPA_GetError
		div ebx
		; finds the ordinal position of the function
		mov edx, dword  [ebp - 0x18]    ; AddressOfNameOrdinals
		mov cx, word  [edx + eax * 0x2] ; NameOrdinal position
		; finds the VA of the function
		mov edx, dword  [ebp - 0x10]      ; AddressOfFunctions
		mov edx, dword  [edx + ecx * 0x4] ; RVA of function
		add edx, dword  [ebp + 0x8]       ; VA of function
		mov eax, edx
		jmp GPA_Exit
		GPA_GetError:
			mov eax, 0xFFFFFFFF
		GPA_Exit:
			mov dword  [ebp - 0x1C], eax
			popad
			mov eax, dword  [ebp - 0x1C]
			leave
			ret 0x8

; calculates the length of passed string
strlen:
    ; ebp - 0x4 (length of string)
    ; ebp
    ; return address
    ; ebp + 0x8	(address of string)
    push ebp
    mov ebp, esp
    sub esp, 0x4
    pushad
    cld
    mov edi, [ebp + 0x8]
    xor ecx, ecx
    mov ecx, 0xFFFFFFFF
    xor eax, eax
    repne scasb
    mov eax, [ebp + 0x8]
    sub edi, eax
    xchg eax, edi
    mov dword [ebp - 0x4], eax
    popad
    mov eax, dword [ebp - 0x4]
    leave
    ret 0x4