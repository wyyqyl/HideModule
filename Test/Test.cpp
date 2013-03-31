/* 
    Copyright [2013] Yorath
    Test.cpp : Defines the entry point for the console application.
*/
#include "stdafx.h"
#include <Windows.h>
#include "../HideModule/dllmain.h"

int main()
{
    HMODULE hModule = LoadLibrary(TEXT("HideModule.dll"));
    if (!hModule) {
        printf_s("Failed to load HideModule.dll");
        return -1;
    }
    //FreeLibrary(hModule);
    //Test(hModule);
    //HMODULE hModule = GetModuleHandle(TEXT("HideModule.dll"));

    while (true) {
        printf_s("The program is running...\n");
        Sleep(10000);
    }
    return 0;
}