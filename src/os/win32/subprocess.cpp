#include "prelude.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct subprocess
{
	HANDLE Process;

	HANDLE Stdout;
	HANDLE Stderr;
	HANDLE Stdin;
};

subprocess *StartSubprocess(const char *executable, const char **args, int numArgs)
{
	subprocess *s = (subprocess*)calloc(1, sizeof(subprocess));

	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa); 
	sa.bInheritHandle = TRUE; 
	sa.lpSecurityDescriptor = NULL; 

	STARTUPINFOA si = { };
	si.cb = sizeof(si);
	si.dwFlags |= STARTF_USESTDHANDLES;

	CreatePipe(&s->Stdout, &si.hStdOutput, &sa, 0);
	CreatePipe(&s->Stderr, &si.hStdError, &sa, 0);
	CreatePipe(&si.hStdInput, &s->Stdin, &sa, 0);
	SetHandleInformation(s->Stdout, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(s->Stderr, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(s->Stdin, HANDLE_FLAG_INHERIT, 0);

	PROCESS_INFORMATION pi = { };

	char cmdLine[1024], *pos = cmdLine;
	pos += sprintf(pos, "\"%s\"", executable);
	for (int i = 0; i < numArgs; i++)
	{
		pos += sprintf(pos, " \"%s\"", args[i]);
	}

	CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	CloseHandle(si.hStdOutput);
	CloseHandle(si.hStdError);
	CloseHandle(si.hStdInput);

	s->Process = pi.hProcess;
	CloseHandle(pi.hThread);
	return s;
}

int ReadSubprocessStdout(subprocess *s, void *buffer, int size)
{
	DWORD numRead;
	ReadFile(s->Stdout, buffer, size, &numRead, NULL);
	return (int)numRead;
}

int ReadSubprocessStderr(subprocess *s, void *buffer, int size)
{
	DWORD numRead;
	ReadFile(s->Stderr, buffer, size, &numRead, NULL);
	return (int)numRead;
}

int WriteSubprocessStdin(subprocess *s, void *buffer, int size)
{
	DWORD numWritten;
	WriteFile(s->Stdin, buffer, size, &numWritten, NULL);
	return (int)numWritten;
}

void WaitForSubprocess(subprocess *s)
{
	WaitForSingleObject(s->Process, INFINITE);
}

void WaitForAnySubprocess(subprocess **s, int num)
{
	HANDLE handles[128];
	int numReal = 0;

	for (int i = 0; i < num; i++)
	{
		if (s[i])
		{
			handles[numReal] = s[i]->Process;
			numReal++;
		}
	}

	WaitForMultipleObjects(numReal, handles, FALSE, INFINITE);
}

void FreeSubprocess(subprocess *s)
{
	CloseHandle(s->Process);
	CloseHandle(s->Stdout);
	CloseHandle(s->Stderr);
	CloseHandle(s->Stdin);

	free(s);
}

bool HasSubprocessExited(subprocess *s, int *retCode)
{
	DWORD code;
	GetExitCodeProcess(s->Process, &code);
	if (code == STILL_ACTIVE)
		return false;

	if (retCode)
		*retCode = (int)code;
	return true;
}
