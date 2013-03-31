// HideModule.cpp : Defines the exported functions for the DLL application.
//

#include "HideModule.h"
#include <stdio.h>
#include <stdarg.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#pragma comment(lib, "Psapi.lib")

typedef
LPVOID WINAPI VIRTUALALLOC(
    _In_opt_  LPVOID lpAddress,
    _In_      SIZE_T dwSize,
    _In_      DWORD flAllocationType,
    _In_      DWORD flProtect
    );

typedef
void *MEMCPY(
    void *dest,
    const void *src,
    size_t count 
    );

typedef
bool UNLOADMODULE(
    HMODULE hModule,
    LPVOID lpNewBaseAddr,
    ULONG_PTR SizeOfImage
    );

typedef
NTSTATUS WINAPI NTQUERYINFORMATIONPROCESS(
    _In_       HANDLE ProcessHandle,
    _In_       PROCESSINFOCLASS ProcessInformationClass,
    _Out_      PVOID ProcessInformation,
    _In_       ULONG ProcessInformationLength,
    _Out_opt_  PULONG ReturnLength
    );

typedef struct _LDR_MODULE
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;


void Print(const LPTSTR fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int len = _vsctprintf(fmt, args);
    LPTSTR buffer = (LPTSTR)new TCHAR[len + 1];
    _vsntprintf_s(buffer, len + 1, _TRUNCATE, fmt, args);
    va_end(args);
    OutputDebugString(buffer);
    delete []buffer;
}

bool IncModuleRefCount(HMODULE hModule) {
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        DbgPrint((TEXT("CreateToolhelp32Snapshot failed, Error: %d\n"), GetLastError()));
        return false;
    }

    MODULEENTRY32 ModuleEntry = { 0 };
    ModuleEntry.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hSnapShot, &ModuleEntry)) {
        DbgPrint((TEXT("Module32First failed, Error: %d\n"), GetLastError()));
        CloseHandle(hSnapShot);
        return false;
    }

    do {
        if (ModuleEntry.hModule != hModule)
            LoadLibrary(ModuleEntry.szModule);
    } while (Module32Next(hSnapShot, &ModuleEntry));

    CloseHandle(hSnapShot);
    return true;
}


bool SetThreadsState(bool IsResume) {
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        DbgPrint((TEXT("CreateToolhelp32Snapshot failed, Error: %d\n"), GetLastError()));
        return false;
    }

    THREADENTRY32 ThreadEntry = { 0 };
    ThreadEntry.dwSize = sizeof(ThreadEntry);
    DWORD ThreadId = GetCurrentThreadId();
    DWORD ProcessId = GetCurrentProcessId();
    if (!Thread32First(hSnapShot, &ThreadEntry)) {
        DbgPrint((TEXT("Thread32First failed, Error: %d\n"), GetLastError()));
        CloseHandle(hSnapShot);
        return false;
    }

    do {
        if (ProcessId == ThreadEntry.th32OwnerProcessID && ThreadId != ThreadEntry.th32ThreadID) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadEntry.th32ThreadID);
            if (hThread != NULL) {
                if (IsResume) {
                    ResumeThread(hThread);
                } else {
                    SuspendThread(hThread);
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnapShot, &ThreadEntry));

    CloseHandle(hSnapShot);
    return true;
}

#ifdef _DEBUG
void PrintModulesInformation() {
    NTQUERYINFORMATIONPROCESS *pfnNtQueryInformationProcess =
        (NTQUERYINFORMATIONPROCESS *)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");
    if (pfnNtQueryInformationProcess != NULL) {
        PROCESS_BASIC_INFORMATION PBI = { 0 };
        DWORD ReturnLength = 0;
        if (NT_SUCCESS(pfnNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &PBI, sizeof(PBI), &ReturnLength))) {
            PLDR_MODULE LdrModule = NULL;
            PLIST_ENTRY Head = PBI.PebBaseAddress->Ldr->InMemoryOrderModuleList.Flink;
            PLIST_ENTRY Current = Head;

            do {
                LdrModule = (PLDR_MODULE)CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                DbgPrint((TEXT("Name: %s, BaseAddress: %p, LoadCount: %d\n"), LdrModule->BaseDllName.Buffer,
                    LdrModule->BaseAddress, LdrModule->LoadCount));
                Current = Current->Flink;
            } while (Current != Head);
        }
    }
}
#else
void PrintModulesInformation() {}
#endif

void AdjustModuleReferenceCount(HMODULE hModule) {
    NTQUERYINFORMATIONPROCESS *pfnNtQueryInformationProcess =
        (NTQUERYINFORMATIONPROCESS *)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");
    if (pfnNtQueryInformationProcess != NULL) {
        PROCESS_BASIC_INFORMATION PBI = { 0 };
        DWORD ReturnLength = 0;
        if (NT_SUCCESS(pfnNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &PBI, sizeof(PBI), &ReturnLength))) {
            PLDR_MODULE LdrModule = NULL;
            PLIST_ENTRY Head = PBI.PebBaseAddress->Ldr->InMemoryOrderModuleList.Flink;
            PLIST_ENTRY Current = Head;

            do {
                LdrModule = (PLDR_MODULE)CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                // The LoadCount of DLLs that are static linked is -1, that kind of DLLs can't be freed
                // by FreeLibrary. So I modify that LoadCount to 1 in case that this DLL is static linked.
                if (LdrModule->BaseAddress == hModule) {
                    // Add the reference count of DLLs that this module relies on
                    LoadLibraryW(LdrModule->BaseDllName.Buffer);
                    LdrModule->LoadCount = 1;
                }
                Current = Current->Flink;
            } while (Current != Head);
        }
    }
}

bool UnloadModule(HMODULE hModule, LPVOID lpNewBaseAddr, ULONG_PTR SizeOfImage)
{
    LPVOID lpBaseOfDll = (LPVOID)hModule;
    MEMCPY *pfnMemCpy = (MEMCPY *)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "memcpy");
    VIRTUALALLOC *pfnVirtualAlloc = (VIRTUALALLOC *)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "VirtualAlloc");
    bool ret = false;

    if (!FreeLibrary(hModule)) {
        DbgPrint((TEXT("FreeLibrary for the module failed, Error: %d\n"), GetLastError()));
    }
    
    // After FreeLibrary, we can't use any functions whose addresses are not retrieved before.
    // And the strings are invalid also.
    LPVOID OriBaseAddr = pfnVirtualAlloc(lpBaseOfDll, SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (OriBaseAddr == NULL) {
        // DbgPrint((TEXT("pfnVirtualAlloc for OriBaseAddr failed, Error: %d\n"), GetLastError()));
    } else if (OriBaseAddr != lpBaseOfDll) {
        // DbgPrint((TEXT("OriBaseAddr is not equal to lpBaseOfDll\n")));
    } else {
        pfnMemCpy(OriBaseAddr, lpNewBaseAddr, SizeOfImage);
        ret = true;
    }
    return ret;
}


void HideModule(HMODULE hModule, bool DeleteAfter) {
    MODULEINFO ModuleInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &ModuleInfo, sizeof(ModuleInfo))) {
        DbgPrint((TEXT("GetModuleInformation failed, Error: %d\n"), GetLastError()));
        return;
    }

    LPVOID lpNewBaseAddr = VirtualAlloc(NULL, ModuleInfo.SizeOfImage,
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpNewBaseAddr == NULL) {
        DbgPrint((TEXT("VirtualAlloc for lpNewBaseAddr failed, Error: %d\n"), GetLastError()));
        return;
    }

    memcpy(lpNewBaseAddr, ModuleInfo.lpBaseOfDll, ModuleInfo.SizeOfImage);
    UNLOADMODULE *pfnUnloadModule = (UNLOADMODULE *)((ULONG_PTR)UnloadModule
        - (ULONG_PTR)ModuleInfo.lpBaseOfDll + (ULONG_PTR)lpNewBaseAddr);

    DbgPrint((TEXT("\n---------------------------------------------------------------------------\n")));
    DbgPrint((TEXT("Check the modules before adjusting the reference count of the loaded modules\n")));
    PrintModulesInformation();

    AdjustModuleReferenceCount(hModule);

    DbgPrint((TEXT("\n-------------------------------------------------------------------------\n")));
    DbgPrint((TEXT("Check the modules after adjusting the reference count of the loaded modules\n")));
    PrintModulesInformation();

    TCHAR FileName[MAX_PATH] = { 0 };
    bool HasFileName = false;
    if (DeleteAfter) {
        if (!GetModuleFileName(hModule, FileName, _countof(FileName))) {
            DbgPrint((TEXT("GetModuleFileName failed, Error: %d\n"), GetLastError()));
        } else {
            HasFileName = true;
        }
    }

    SetThreadsState(false);
    // Jump to the new space, and free the original dll in the new space
    if (!pfnUnloadModule(hModule, lpNewBaseAddr, ModuleInfo.SizeOfImage)) {
        DbgPrint((TEXT("UnloadModule failed, Error: %d\n"), GetLastError()));
    }
    // Jump back to the original space
    SetThreadsState(true);
    
    DbgPrint((TEXT("\n--------------------------------------------\n")));
    DbgPrint((TEXT("Check the modules after FreeLibrary is called\n")));
    PrintModulesInformation();

    if (!VirtualFree(lpNewBaseAddr, 0, MEM_DECOMMIT)) {
        DbgPrint((TEXT("VirtualFree for lpNewBaseAddr failed, Error: %d\n"), GetLastError()));
    }

    if (HasFileName) {
        if (!DeleteFile(FileName)) {
            DbgPrint((TEXT("DeleteFile failed, Error: %d\n"), GetLastError()));
        }
    }
}
