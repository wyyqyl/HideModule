
#pragma once

#include <Windows.h>

void HideModule(HMODULE hModule, bool DeleteAfter);

#ifdef _DEBUG
void Print(const LPTSTR fmt, ...);
#define DbgPrint(_x_) Print _x_
#else
#define DbgPrint(_x_)
#endif