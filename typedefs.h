#ifndef _TYPEDEFS_H
#define _TYPEDEFS_H

#include<windows.h>

/*
 definitions
*/
#define WCHAR_EXIST(x, y) wcscmp(x, y) == 0

typedef struct dllpath
{
	BOOL dllpathArg;
	LPWSTR dllpath;
} DLLPathArg;

typedef struct process
{
	BOOL processArg;
	LPWSTR processName;
	INT proccessPID;
} ProcessArg;

#endif // _TYPEDEFS_H