#include "prelude.h"
#include <stdlib.h>

struct subprocess
{
	pid_t Pid;

	int Stdout;
	int Stderr;
	int Stdin;

	int ExitCode;
	bool HasExited;
};

static pthread_mutex_t gSubprocessMutex = PTHREAD_MUTEX_INITIALIZER;
static pid_t gSubprocessPids[1024];
static subprocess *gSubprocessPointers[1024];
int gNumSubprocesses = 0;

subprocess *StartSubprocess(const char *executable, const char **args, int numArgs)
{
	char *copyArgs[128];
	copyArgs[0] = (char*)executable;
	for (int i = 0; i < numArgs; i++)
	{
		copyArgs[i + 1] = (char*)args[i];
	}
	copyArgs[numArgs + 1] = NULL;


	int stdoutPipe[2];
	int stderrPipe[2];
	int stdinPipe[2];

	pipe(stdoutPipe);
	pipe(stderrPipe);
	pipe(stdinPipe);

	pid_t pid = vfork();

	if (pid == 0)
	{
		dup2(stdoutPipe[1], STDOUT_FILENO);
		dup2(stderrPipe[1], STDERR_FILENO);
		dup2(stdinPipe[0], STDIN_FILENO);
		close(stdoutPipe[0]);
		close(stderrPipe[0]);
		close(stdinPipe[1]);

		execv(executable, copyArgs);

		// Should never return, just failsafe
		_exit(1);
		return NULL;
	}
	else
	{
		subprocess *s = (subprocess*)calloc(1, sizeof(subprocess));
		s->Pid = pid;
		s->Stdout = stdoutPipe[0];
		s->Stderr = stderrPipe[0];
		s->Stdin = stdinPipe[1];
		s->HasExited = false;
		close(stdoutPipe[1]);
		close(stderrPipe[1]);
		close(stdinPipe[0]);

		pthread_mutex_lock(&gSubprocessMutex);

		int num = gNumSubprocesses;
		gSubprocessPids[num] = pid;
		gSubprocessPointers[num] = s;
		gNumSubprocesses = num + 1;

		pthread_mutex_unlock(&gSubprocessMutex);

		return s;
	}
}

int ReadSubprocessStdout(subprocess *s, void *buffer, int size)
{
	return (int)read(s->Stdout, buffer, size);
}

int ReadSubprocessStderr(subprocess *s, void *buffer, int size)
{
	return (int)read(s->Stderr, buffer, size);
}

int WriteSubprocessStdin(subprocess *s, void *buffer, int size)
{
	return (int)write(s->Stdin, buffer, size);
}

static int GetExitCodeFromStatus(int wstatus)
{
	if (WIFEXITED(wstatus))
		return WEXITSTATUS(wstatus);
	else
		return 256;
}

void WaitForSubprocess(subprocess *s)
{
	if (s->HasExited)
		return;

	int wstatus;
	waitpid(s->Pid, &wstatus, 0);
	s->ExitCode = GetExitCodeFromStatus(wstatus);
	s->HasExited = true;
}

void WaitForAnySubprocess(subprocess **s, int num)
{
	bool allExited = true;
	for (int i = 0; i < num; i++)
	{
		if (s[i] && !s[i]->HasExited)
		{
			allExited = false;
			break;
		}
	}

	if (allExited)
		return;

	for (;;)
	{
		// Wait for any child process
		int wstatus;
		pid_t pid = waitpid(-1, &wstatus, 0);
		int exitCode = GetExitCodeFromStatus(wstatus);

		// If the child process is one of the waited ones, set the exit code and return
		for (int i = 0; i < num; i++)
		{
			if (s[i] && s[i]->Pid == pid)
			{
				s[i]->ExitCode = exitCode;
				s[i]->HasExited = true;
				return;
			}
		}

		// If it was some other subprocess we need to store the exit code before we forget it
		// Walk through all active child processes (slow!)
		{
			pthread_mutex_lock(&gSubprocessMutex);

			int num = gNumSubprocesses;
			for (int i = 0; i < num; i++)
			{
				if (gSubprocessPids[i] == pid)
				{
					subprocess *s = gSubprocessPointers[i];
					s->ExitCode = exitCode;
					s->HasExited = true;
					break;
				}
			}

			pthread_mutex_unlock(&gSubprocessMutex);
		}
	}
}

void FreeSubprocess(subprocess *s)
{
	close(s->Stdout);
	close(s->Stderr);
	close(s->Stdin);

	pthread_mutex_lock(&gSubprocessMutex);

	int index, num = gNumSubprocesses;
	for (index = 0; index < num; index++)
	{
		if (gSubprocessPointers[index] == s)
			break;
	}

	gSubprocessPids[index] = gSubprocessPids[num];
	gSubprocessPointers[index] = gSubprocessPointers[num];
	gNumSubprocesses = num - 1;

	pthread_mutex_unlock(&gSubprocessMutex);
}

bool HasSubprocessExited(subprocess *s, int *retCode)
{
	if (s->HasExited)
	{
		if (retCode)
			*retCode = s->ExitCode;
		return true;
	}

	int wstatus;
	pid_t ret = waitpid(s->Pid, &wstatus, WNOHANG);
	if (ret == 0)
		return false;

	int exitCode = GetExitCodeFromStatus(wstatus);
	s->ExitCode = exitCode;
	s->HasExited = true;
	if (retCode)
		*retCode = exitCode;
	return true;
}

