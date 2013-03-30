
#pragma once

#include <Windows.h>

void HideModule(HMODULE hModule, bool DeleteAfter);

#ifdef _DEBUG
void DebugPrint(const LPTSTR fmt, ...);
#define DbgPrint DebugPrint
#else
#define DbgPrint
#endif