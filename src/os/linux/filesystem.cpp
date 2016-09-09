#include "prelude.h"
#include "os/filesystem.h"

bool CreateFolderSimple(const char *path)
{
	return mkdir(path, 0777) == 0;
}

