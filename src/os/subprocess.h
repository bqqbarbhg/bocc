#pragma once

struct subprocess;

subprocess *StartSubprocess(const char *executable, const char **args, int numArgs);
void FreeSubprocess(subprocess *s);

int ReadSubprocessStdout(subprocess *s, void *buffer, int size);
int ReadSubprocessStderr(subprocess *s, void *buffer, int size);
int WriteSubprocessStdin(subprocess *s, void *buffer, int size);

void WaitForSubprocess(subprocess *s);
void WaitForAnySubprocess(subprocess **s, int num);

bool HasSubprocessExited(subprocess *s, int *retCode);

