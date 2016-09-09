#include "prelude.h"
#include "test_support.h"
#include "os/crash.h"
#include <string.h>
#include <stdio.h>

char testDirectory[256];

int main(int argc, char **argv)
{
	if (argc == 1)
	{
		fprintf(stderr, "Expected 'list' or 'run'\n");
		return 1;
	}

	SetSilentCrashMode();

#if defined(OS_WINDOWS)
	{
		char *selfEnd = strrchr(argv[0], '\\');
		sprintf(testDirectory, "%.*s\\testout\\", (int)(selfEnd - argv[0]), argv[0]);
	}
#elif defined(OS_LINUX)
	{
		char *selfEnd = strrchr(argv[0], '/');
		sprintf(testDirectory, "%.*s/testout/", (int)(selfEnd - argv[0]), argv[0]);
	}
#endif

	testTempDirectory = testDirectory;

	if (!strcmp(argv[1], "list"))
	{
		ListAllTestCases();
		return 0;
	}
	else if (!strcmp(argv[1], "run"))
	{
		return RunTestCase(argv[2]);
	}
	else
	{
		return 1;
	}
}

