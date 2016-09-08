#pragma once

#if defined(OS_WINDOWS)
#define OsDebugBreak() __debugbreak()
#elif defined(OS_LINUX)
#define OsDebugBreak() __builtin_trap()
#endif

