#ifndef _CONSOLE_H
#define _CONSOLE_H
#include<windows.h>

#define SET_CONSOLE_ATTRIBUTE(console, attrib) SetConsoleTextAttribute(console, attrib)

/*
Color Attributes
*/
#define DEFAULT_CONSOLE_ATTRIBUTE 0x00007
#define OK_OPERATION_ATTRIBUTE 0x00002
#define NOTE_OPERATION_ATTRIBUTE 0x00005
#define ERROR_OPERATION_ATTRIBUTE 12
#define INFO_OPERATION_ATTRIBUTE 15

VOID SendConsoleError(HANDLE hConsole, CONST PCHAR msg);
VOID SendConsoleLastError(HANDLE hConsole, CONST PCHAR msg);
VOID SendConsoleInfo(HANDLE hConsole, CONST PCHAR msg);
VOID SendConsoleOK(HANDLE hConsole, CONST PCHAR msg);
VOID SendConsoleNote(HANDLE hConsole, CONST PCHAR msg);
VOID SendConsoleHelp(HANDLE hConsole, WCHAR* path, BOOL isAdmin);

/* 
Utilities
*/
WCHAR* GetConsoleExeName(WCHAR* path);

#endif // _CONSOLE_H