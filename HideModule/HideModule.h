
#pragma once

#include <Windows.h>

void HideModule(HMODULE hModule, bool DeleteAfter);

void Print(const LPTSTR fmt, ...);
#ifdef _DEBUG
#define DbgPrint(_x_) Print _x_
#else
#define DbgPrint(_x_)
#endif