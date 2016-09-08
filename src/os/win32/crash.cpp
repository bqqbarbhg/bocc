#include "prelude.h"

void SetSilentCrashMode()
{
	SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
}

