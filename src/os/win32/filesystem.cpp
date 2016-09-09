#include "prelude.h"
#include "os/filesystem.h"

bool CreateFolderSimple(const char *path)
{
	return CreateDirectoryA(path, NULL) != 0;
}

