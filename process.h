#ifndef _PROCESS_H
#define _PROCESS_H
#include<windows.h>
#include<winnt.h>

#ifdef _WIN64
#define CURRENT_ARCHITECTURE IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCHITECTURE IMAGE_FILE_MACHINE_I386
#endif

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

typedef HINSTANCE(WINAPI* f_LoadLibraryA)(const char* lpLibFilename);
typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
typedef BOOL(WINAPIV* f_RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

typedef struct __DLL_INFO
{
	PBYTE dllBytes;
	DWORD32 dllSize;
} DLL_INFO;

typedef struct __MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
} MANUAL_MAPPING_DATA;

BOOL IsCorrectTargetArchitecture(HANDLE hConsole, HANDLE hProc);
DWORD GetProcessPIDByName(LPWSTR name);
LPWSTR GetProcessNameByPID(DWORD pid);
VOID AdjustDebugPrivilege();
BOOL InjectDLL(HANDLE hConsole, HANDLE hProc, DLL_INFO dllSize);
VOID WINAPI Shellcode(MANUAL_MAPPING_DATA* pData);

#endif // _PROCESS_H