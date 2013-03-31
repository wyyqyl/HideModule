
#pragma once

#include <Windows.h>

void HideModule(HMODULE hModule, bool DeleteAfter);

#ifdef _DEBUG
#define DbgPrint(_x_) Print _x_
#else
#define DbgPrint(_x_)
#endif