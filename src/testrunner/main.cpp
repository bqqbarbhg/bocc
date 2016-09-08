#include "os/subprocess.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static char testList[1024*1024];

struct test
{
	char Name[128];

	char Stdout[1024];
	int StdoutLen;

	char Stderr[1024];
	int StderrLen;

	int ReturnCode;
};

test tests[1024];

int main(int argc, char **argv)
{
	char testExe[1024];

#if defined(OS_WINDOWS)
	{
		char *selfEnd = strrchr(argv[0], '\\');
		sprintf(testExe, "%.*s\\test.exe", selfEnd - argv[0], argv[0]);
	}
#elif defined(OS_LINUX)
	{
		char *selfEnd = strrchr(argv[0], '/');
		sprintf(testExe, "%.*s/test", selfEnd - argv[0], argv[0]);
	}
#endif

	int numTests = 0;

	{
		const char *args[] = { "list" };
		subprocess *listProc = StartSubprocess(testExe, args, 1);
		int testListLength = ReadSubprocessStdout(listProc, testList, sizeof(testList));
		int listRet;
		do {
			WaitForSubprocess(listProc);
		} while (!HasSubprocessExited(listProc, &listRet));
		FreeSubprocess(listProc);

		int testListPos = 0;
		while (testListPos != testListLength)
		{
			int begin = testListPos;
			while (testList[testListPos] != '\r' && testList[testListPos] != '\n')
				testListPos++;
			int end = testListPos;
			while (testList[testListPos] == '\r' || testList[testListPos] == '\n')
				testListPos++;

			test *t = &tests[numTests++];
			memcpy(t->Name, testList + begin, end - begin);
			t->Name[end - begin] = '\0';
		}
	}

	int numFail = 0;
	{
		int concurrent = 4;
		subprocess *procs[64] = { 0 };
		int testIndex[64] = { 0 };
		int currentTest = 0;

		for (;;)
		{
			int numDone = 0;
			for (int i = 0; i < concurrent; i++)
			{
				if (procs[i] != NULL)
					continue;

				if (currentTest < numTests)
				{
					testIndex[i] = currentTest;

					const char *args[] = { "run", tests[currentTest].Name };
					procs[i] = StartSubprocess(testExe, args, 2);

					currentTest++;
				}
				else
				{
					numDone++;
				}
			}

			if (numDone == concurrent)
				break;

			WaitForAnySubprocess(procs, concurrent);

			for (int i = 0; i < concurrent; i++)
			{
				if (!procs[i])
					continue;

				int ret;
				if (!HasSubprocessExited(procs[i], &ret))
					continue;

				if (ret != 0)
					numFail++;

				char c = ret == 0 ? '.' : 'F';
				putchar(c);
				fflush(stdout);

				test *t = &tests[testIndex[i]];
				t->ReturnCode = ret;
				t->StdoutLen = ReadSubprocessStdout(procs[i], t->Stdout, sizeof(t->Stdout));
				t->StderrLen = ReadSubprocessStderr(procs[i], t->Stderr, sizeof(t->Stderr));
				FreeSubprocess(procs[i]);
				procs[i] = NULL;
			}
		}
	}

	{
		printf("\n\nPassed %d/%d tests\n\n", numTests - numFail, numTests);

		for (int i = 0; i < numTests; i++)
		{
			test *t = &tests[i];
			if (t->ReturnCode != 0)
			{
				printf("Test failed: %s\n%.*s\n", t->Name, t->StderrLen, t->Stderr);
			}
		}
	}

	return numFail == 0 ? 0 : 1;
}
