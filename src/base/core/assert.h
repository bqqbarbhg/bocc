#pragma once

#include "os/debug.h"

#define Assert(x) do { if (!(x)) { OsDebugBreak(); } } while(0)

