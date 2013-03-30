
#pragma once

#include <Windows.h>

#ifdef HIDEMODULE_EXPORTS
#define HIDEMODULE_API __declspec(dllexport)
#else
#define HIDEMODULE_API __declspec(dllimport)
#endif

HIDEMODULE_API void Test(HMODULE hModule);