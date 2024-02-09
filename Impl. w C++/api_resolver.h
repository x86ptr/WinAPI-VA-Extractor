#include <iostream>
#include <regex>
#include <windows.h>
#include <winternl.h>

/* This function compares module names */
BOOL CompareModuleHashName(wchar_t* PEB_ModuleName, const char* User_ModuleName)
{
	char buffer[128];
	std::smatch DLLName;

	/* Converts unicode to char* */
	wcstombs(buffer, PEB_ModuleName, sizeof(buffer));

	/* Separates DLL's name of DLL's path */
	std::string stringBuff = std::string(buffer);
	std::regex_search(stringBuff, DLLName, std::regex("([^\\\\]+)$"));
	strcpy_s(buffer, sizeof(buffer), DLLName.str().c_str());
	/* Converts to lowercase letters */
	for (size_t i = 0; i < strlen(buffer); i++)
		buffer[i] = tolower(buffer[i]);

	if(!strcmp(buffer, User_ModuleName))
		return TRUE;

	return FALSE;
}

/* This function retrieves the base address of the target module */
PVOID _GetModuleHandle(const char* ModuleName)
{
	_TEB* TEB = NtCurrentTeb();
	PPEB PEB = TEB->ProcessEnvironmentBlock;
	PPEB_LDR_DATA Ldr = PEB->Ldr;
	PLIST_ENTRY FirstNode = Ldr->InMemoryOrderModuleList.Flink;

	PLDR_DATA_TABLE_ENTRY PEB_LDR_DATA_TABLE_ENTRY;
	do {
		/* For typecast to PEB_LDR_DATA_TABLE_ENTRY, it must be point to the start position of LDR_DATA_TABLE_ENTRY structure */
		#ifdef _M_X64
			FirstNode = (PLIST_ENTRY)((char*)FirstNode - 0x10);
		#else
			FirstNode = (PLIST_ENTRY)((char*)FirstNode - 0x8);
		#endif
		
		PEB_LDR_DATA_TABLE_ENTRY = (PLDR_DATA_TABLE_ENTRY)FirstNode;

		/* Compares module names */
		if (CompareModuleHashName(PEB_LDR_DATA_TABLE_ENTRY->FullDllName.Buffer, ModuleName))
			return PEB_LDR_DATA_TABLE_ENTRY->DllBase;

		FirstNode = (PLIST_ENTRY)PEB_LDR_DATA_TABLE_ENTRY->InMemoryOrderLinks.Flink;
	} while (FirstNode != &Ldr->InMemoryOrderModuleList);

	return NULL;
}

/* This function fetches the VA of the exported target function */
PVOID _GetProcAddress(const char* FuncName, PVOID BaseAddress)
{
	if(BaseAddress == NULL)
		return NULL;
	
	PIMAGE_DOS_HEADER DOS_H = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_OPTIONAL_HEADER OPTIONAL_H = (PIMAGE_OPTIONAL_HEADER)(
		(DWORD_PTR)BaseAddress + DOS_H->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
		);
	PIMAGE_EXPORT_DIRECTORY EXPORT_DIR = (PIMAGE_EXPORT_DIRECTORY)(
		(LPBYTE)BaseAddress + OPTIONAL_H->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
		);

	PDWORD AddressOfFunctions = (PDWORD)((LPBYTE)BaseAddress + EXPORT_DIR->AddressOfFunctions);
	PWORD AddressOfNameOrdinals = (PWORD)((LPBYTE)BaseAddress + EXPORT_DIR->AddressOfNameOrdinals);
	PDWORD AddressOfNames = (PDWORD)((LPBYTE)BaseAddress + EXPORT_DIR->AddressOfNames);

	for (DWORD i = 0; i < EXPORT_DIR->NumberOfNames; i++) {
    	const char* functionName = (const char*)((uintptr_t)BaseAddress + AddressOfNames[i]);

		if (!strcmp(functionName, FuncName)) {
			// Retrieve the RVA of the function
			DWORD functionRVA = AddressOfFunctions[AddressOfNameOrdinals[i]];
			// Calculate the function's virtual address
			PVOID functionVA = (PVOID)((uintptr_t)BaseAddress + functionRVA);
			return functionVA;
		}
	}

	return NULL;
}