// dllmain.cpp : Defines the entry point for the DLL application.

#include "dllmain.h"
#include "HideModule.h"
#include <stdio.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //AdjustModuleRefCount(hModule);
        HideModule(hModule, true);
        //while (true) {
        //    //printf_s("The dll is running...\n");
        //    Sleep(1000);
        //}
        //FreeLibrary(hModule);
        break;
    case DLL_PROCESS_DETACH:
        printf_s("The dll is detached!!!!!!!!!!!!!!\n");
    	break;
    }
    
	return TRUE;
}

void Test(HMODULE hModule) {
    //AdjustModuleRefCount(hModule);
}