#include "console.h"
#include "typedefs.h"
#include "process.h"
#include<stdio.h>

BOOL runnedAsAdmin() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) fRet = Elevation.TokenIsElevated;
	}
	if (hToken) CloseHandle(hToken);
	return fRet;
}

DLL_INFO ExtractDLL(HANDLE hConsole, LPWSTR dllPath)
{
	DLL_INFO dll = { NULL, 0 };
	HANDLE hFile;
	DWORD dwFileSize, dwBytesRead;
	PBYTE Data = NULL;
	hFile = CreateFile(dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		SendConsoleLastError(hConsole, "[-] Cannot open the dll file.");
		return dll;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	if(dwFileSize == INVALID_FILE_SIZE)
	{
		SendConsoleLastError(hConsole, "[-] Cannot get dll file size.");
		CloseHandle(hFile);
		return dll;
	}
	dll.dllSize = dwFileSize;
	printf("[+] DLL Path Size --> %d bytes\n", dll.dllSize);
	Data = (PBYTE)malloc(dwFileSize);
	if (!Data)
	{
		SendConsoleError(hConsole, "[-] Cannot allocate the dll file.\n");
		free(Data);
		CloseHandle(hFile);
		return dll;
	}
	if (!ReadFile(hFile, Data, dwFileSize, &dwBytesRead, NULL))
	{
		free(Data);
		CloseHandle(hFile);
		return dll;
	}
	CloseHandle(hFile);
	dll.dllBytes = Data;
	return dll;
}

INT main(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nCmdShow)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	INT argc;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);
	DLLPathArg dllarg = {FALSE, (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t))};
	ProcessArg processarg = {FALSE, L"\0", 0};
	INT ProcessPID;
	HANDLE hProc;
	PBYTE bytes = NULL;
	SendConsoleHelp(hConsole, argv[0], runnedAsAdmin());
	for (INT i = 1; i < argc; ++i)
	{
		if (WCHAR_EXIST(argv[i], L"-dllpath"))
		{
			dllarg.dllpathArg = TRUE;
			if (i + 1 == argc)
			{
				SendConsoleError(hConsole, "[-] DLL Path can't be empty.\n");
			}
			else if (wcsncmp(argv[i + 1], L"-", 1))
			{
				dllarg.dllpath = argv[i + 1];
			}
			else
			{
				SendConsoleError(hConsole, "[-] DLL Path isn't valid.\n");
			}
		}
		else if (WCHAR_EXIST(argv[i], L"-pid") || WCHAR_EXIST(argv[i], L"-process"))
		{
			processarg.processArg = TRUE;
			if (i + 1 == argc)
			{
				SendConsoleError(hConsole, "[-] Process name/PID can't be empty.\n");
			}
			else if (wcsncmp(argv[i + 1], L"-", 1))
			{
				if (WCHAR_EXIST(argv[i], L"-pid")) processarg.proccessPID = _wtoi(argv[i + 1]);
				else processarg.processName = argv[i + 1];
			}
			else
			{
				SendConsoleError(hConsole, "[-] Process name/PID isn't valid.\n");
			}
		}
	}
	//LocalFree(argv);
	if (!dllarg.dllpathArg)
	{
		SendConsoleError(hConsole, "[-] DLL Path is required argument.\n");
		goto EXIT;
	}

	if (!processarg.processArg)
	{
		SendConsoleError(hConsole, "[-] Process name/PID is required argument.\n");
		goto EXIT;
	}
	AdjustDebugPrivilege();

	ProcessPID = processarg.proccessPID == 0 ? GetProcessPIDByName(processarg.processName) : processarg.proccessPID;
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessPID);
	if (!hProc)
	{
		SendConsoleLastError(hConsole, "[-] Unable to start the process.");
		goto EXIT;
	}

	SET_CONSOLE_ATTRIBUTE(hConsole, INFO_OPERATION_ATTRIBUTE);
	printf("[+] Process Name --> %ws\n", processarg.processName == L"\0" ? GetProcessNameByPID(ProcessPID) : processarg.processName); /// BUG
	printf("[+] Process PID --> %d\n", ProcessPID);
	if (!IsCorrectTargetArchitecture(hConsole, hProc)) {
		SendConsoleLastError(hConsole, "[-] The process architecture is not same as injector.");
		CloseHandle(hProc);
		goto EXIT;
	}
	
	if (GetFileAttributes(dllarg.dllpath) == INVALID_FILE_ATTRIBUTES) {
		SendConsoleError(hConsole, "[-] DLL Path could not be found.\n");
		CloseHandle(hProc);
		goto EXIT;
	}
	printf("[+] DLL Path --> %ws\n", dllarg.dllpath);
	DLL_INFO dll_info = ExtractDLL(hConsole, dllarg.dllpath);

	if (InjectDLL(hConsole, hProc, dll_info))
	{
		SendConsoleOK(hConsole, "[+] Injection Successfull.\n");
	}
	else
	{
		SendConsoleError(hConsole, "[-] Injection Failed.\n");
	}
	free(dll_info.dllBytes);
	CloseHandle(hProc);
EXIT:
	SET_CONSOLE_ATTRIBUTE(hConsole, DEFAULT_CONSOLE_ATTRIBUTE);
	CloseHandle(hConsole);
	return EXIT_SUCCESS;
		
}
