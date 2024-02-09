#include "api_resolver.h"

typedef HANDLE(WINAPI* MyCreateThread)(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

VOID WINAPI MyThreadFunc(PVOID params)
{
    printf("Thread ID: %d\n", GetCurrentThreadId());
}

int main(int argc, char const* argv[])
{
    MyCreateThread _CreateThread = NULL;
    _CreateThread = (MyCreateThread)_GetProcAddress("CreateThread", _GetModuleHandle("kernel32.dll"));

    HANDLE hThread = _CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MyThreadFunc, NULL, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE)
        return EXIT_FAILURE;

    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
