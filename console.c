#include "console.h"
#include<stdio.h>

WCHAR* GetConsoleExeName(WCHAR* path)
{
    BOOL flag = 0;
    for (size_t i = wcslen(path) - 1; i > 0; i--)
    {
        if (path[i] == '\\' || path[i] == '//' || path[i] == '/')
        {
            flag = 1;
            path = path + i + 1;
            break;
        }
    }
    return path;
}

VOID SendConsoleError(HANDLE hConsole, CONST PCHAR msg)
{
	SET_CONSOLE_ATTRIBUTE(hConsole, ERROR_OPERATION_ATTRIBUTE);
	printf("%s", msg);
}

VOID SendConsoleLastError(HANDLE hConsole, CONST PCHAR msg)
{
    SET_CONSOLE_ATTRIBUTE(hConsole, ERROR_OPERATION_ATTRIBUTE);
    printf("%s (Last Error --> 0x%X)\n", msg, GetLastError());
}

VOID SendConsoleInfo(HANDLE hConsole, CONST PCHAR msg)
{
	SET_CONSOLE_ATTRIBUTE(hConsole, INFO_OPERATION_ATTRIBUTE);
	printf("%s", msg);
}

VOID SendConsoleOK(HANDLE hConsole, CONST PCHAR msg)
{
	SET_CONSOLE_ATTRIBUTE(hConsole, OK_OPERATION_ATTRIBUTE);
	printf("%s", msg);
}

VOID SendConsoleNote(HANDLE hConsole, CONST PCHAR msg)
{
	SET_CONSOLE_ATTRIBUTE(hConsole, NOTE_OPERATION_ATTRIBUTE);
	printf("%s", msg);
}

VOID SendConsoleHelp(HANDLE hConsole, WCHAR* path, BOOL isAdmin)
{
    WCHAR* getExecutableName = GetConsoleExeName(path);
	printf("%ws - Simple Manual Map Injector made by P.A\nUsage: %ws [-dllpath X] [-process X | -pid X].\n", getExecutableName, getExecutableName);
    if (!isAdmin)
    {
        SendConsoleNote(hConsole, "[!] The program may not work because does not contains admin rights.\n");
    }
}