This PoC enables the retrieval of the virtual address without relying on direct Windows API calls.

## Detail
The **PEB_LDR_DATA** structure, located within the **Process Environment Block (PEB)**, is a Windows structure that contains information about all the loaded modules in the current process. It points to a linked list of **LDR_DATA_TABLE_ENTRY** structures, each representing details such as the base address, size, and entry point of a loaded module.

#### _PEB
```C++
struct _PEB {
    // ...
    PPEB_LDR_DATA Ldr;
    // ...
};
```

#### _PEB_LDR_DATA
```C++
struct _PEB_LDR_DATA
{
    // ...
    _LIST_ENTRY InLoadOrderModuleList;
    _LIST_ENTRY InMemoryOrderModuleList;
    _LIST_ENTRY InInitializationOrderModuleList;
    // ...
}; 
```

#### _LDR_DATA_TABLE_ENTRY
```C++
struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
};
```

Obtaining the base address of the desired DLL enables the analysis of its Portable Executable (PE) structure. Within this analysis, you will discover the **Export Address Table (EAT)** field, among others. The EAT includes details such as the function name/address's RVA, the starting ordinal number for exported functions, total counts of functions and names, etc.

