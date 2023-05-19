#include "process.h"
#include "console.h"
#include <tlhelp32.h>
#include <stdio.h>

VOID AdjustDebugPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	BOOL success = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
		{
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		}
		CloseHandle(hToken);
	}
}

BOOL IsCorrectTargetArchitecture(HANDLE hConsole, HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		SendConsoleLastError(hConsole, "[-] Can't confirm target process architecture.");
		return FALSE;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);
	return (bTarget == bHost);
}

DWORD GetProcessPIDByName(LPWSTR name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (_wcsicmp(entry.szExeFile, name) == 0) {
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}
		}
	}
	CloseHandle(snapshot);
	return 0;
}

LPWSTR GetProcessNameByPID(DWORD pid)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (entry.th32ProcessID == pid) {
				CloseHandle(snapshot);
				return entry.szExeFile;
			}
		}
	}
	CloseHandle(snapshot);
	return 0;
}

BOOL InjectDLL(HANDLE hConsole, HANDLE hProc, DLL_INFO dllinfo)
{
	IMAGE_NT_HEADERS* pOldNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = NULL;
	IMAGE_FILE_HEADER* pOldFileHeader = NULL;
	BYTE* pTargetBase = NULL;

	//  Variables
	BOOL ClearHeader = TRUE;
	BOOL ClearNonNeededSections = TRUE;
	BOOL AdjustProtections = TRUE;
	BOOL SEHExceptionSupport = TRUE;
	DWORD fdwReason = DLL_PROCESS_ATTACH;
	LPVOID lpReserved = 0;

	if ((*(IMAGE_DOS_HEADER*)dllinfo.dllBytes).e_magic != 0x5A4D) // If file signature is not MZ
	{
		SendConsoleError(hConsole, "[-] Dll file signature is not valid. (It's not MZ).\n");
		return FALSE;
	}

	pOldNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)dllinfo.dllBytes + ((IMAGE_DOS_HEADER*)dllinfo.dllBytes)->e_lfanew);;
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != CURRENT_ARCHITECTURE) {
		SendConsoleError(hConsole, "[-] Machine's architecture is not same as the injector.\n");
		printf("[-] Machine's architecture is: %s\n", pOldFileHeader->Machine == IMAGE_FILE_MACHINE_I386 ? "I386" : "AMD64");
		printf("[-] Your architecture is: %s\n", CURRENT_ARCHITECTURE == IMAGE_FILE_MACHINE_I386 ? "I386" : "AMD64");
		return FALSE;
	}

	pTargetBase = (BYTE*)(VirtualAllocEx(hProc, NULL, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {
		SendConsoleLastError(hConsole, "[-] Target process memory allocation failed.\n");
		return FALSE;
	}

	DWORD oldp = 0;
	VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	MANUAL_MAPPING_DATA data = {0};
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
	SEHExceptionSupport = FALSE;
#endif
	data.pbase = pTargetBase;
	data.fdwReasonParam = fdwReason;
	data.reservedParam = lpReserved;
	data.SEHSupport = SEHExceptionSupport;

	// File header
	if (!WriteProcessMemory(hProc, pTargetBase, dllinfo.dllBytes, 0x1000, NULL)) { //only first 0x1000 bytes for the header
		SendConsoleLastError(hConsole, "[-] Can't write to the process memory.");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return FALSE;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, dllinfo.dllBytes + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, NULL)) {
				SendConsoleLastError(hConsole, "[-] Can't map memory sections.");
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return FALSE;
			}
		}
	}

	BYTE* MappingDataAlloc = (BYTE*)(VirtualAllocEx(hProc, NULL, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		SendConsoleLastError(hConsole, "[-] Target process mapping allocation failed.");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return FALSE;
	}

	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), NULL)) {
		SendConsoleLastError(hConsole, "[-] Can't write mapping to target.");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return FALSE;
	}

	//Shell code
	void* pShellcode = VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		SendConsoleLastError(hConsole, "[-] Memory shellcode allocation failed.");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return FALSE;
	}
	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, NULL)) {
		SendConsoleLastError(hConsole, "[-] Can't write shellcode to target.");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return FALSE;
	}

	printf("[+] Mapped DLL Pointer --> 0x%p\n", pTargetBase);
	printf("[+] Mapping Info Pointer --> 0x%p\n", MappingDataAlloc);
	printf("[+] Shell Code Pointer --> 0x%p\n", Shellcode);

	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, MappingDataAlloc, 0, NULL);
	if (!hThread) {
		SendConsoleLastError(hConsole, "[-] Failed to create a process thread.");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return FALSE;
	}
	CloseHandle(hThread);

	printf("[+] Thread created at --> 0x%p\n", pShellcode);

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		DWORD exitcode = 0;
		GetExitCodeProcess(hProc, &exitcode);
		if (exitcode != STILL_ACTIVE) {
			SendConsoleLastError(hConsole, "[-] Process crashed.");
			return FALSE;
		}

		MANUAL_MAPPING_DATA data_checked = {0};
		ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), NULL);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) {
			SendConsoleLastError(hConsole, "[-] Invalid mapping pointer.");
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return FALSE;
		}
		else if (hCheck == (HINSTANCE)0x505050) {
			SendConsoleNote(hConsole, "[-] Exception support failed.\n");
		}
		Sleep(10);
	}

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
	if (emptyBuffer == NULL) {
		SendConsoleError(hConsole, "[-] Unable to allocate memory.\n");
		return FALSE;
	}
	memset(emptyBuffer, 0, 1024 * 1024 * 20);

	//CLEAR PE HEAD
	if (ClearHeader) {
		if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, NULL)) {
			SendConsoleNote(hConsole, "[-] Can't clear PE Header.\n");
		}
	}

	if (ClearNonNeededSections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
					strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
					strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
					SET_CONSOLE_ATTRIBUTE(hConsole, NOTE_OPERATION_ATTRIBUTE);
					printf("[!] Processing %s removal.\n", pSectionHeader->Name);
					SET_CONSOLE_ATTRIBUTE(hConsole, DEFAULT_CONSOLE_ATTRIBUTE);
					if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, NULL)) {
						SET_CONSOLE_ATTRIBUTE(hConsole, ERROR_OPERATION_ATTRIBUTE);
						printf("[!] Can't clear section %s --> 0x%x.\n", pSectionHeader->Name, GetLastError());
						SET_CONSOLE_ATTRIBUTE(hConsole, DEFAULT_CONSOLE_ATTRIBUTE);
					}
				}
			}
		}
	}

	if (AdjustProtections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				DWORD old = 0;
				DWORD newP = PAGE_READONLY;

				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
					newP = PAGE_READWRITE;
				}
				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
					newP = PAGE_EXECUTE_READ;
				}
				if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
					SET_CONSOLE_ATTRIBUTE(hConsole, NOTE_OPERATION_ATTRIBUTE);
					printf("[!] Section %s set as 0x%lX.\n", (char*)pSectionHeader->Name, newP);
					SET_CONSOLE_ATTRIBUTE(hConsole, DEFAULT_CONSOLE_ATTRIBUTE);
				}
				else {
					SET_CONSOLE_ATTRIBUTE(hConsole, ERROR_OPERATION_ATTRIBUTE);
					printf("[!] Fail section %s set as 0x%lX.\n", (char*)pSectionHeader->Name, newP);
					SET_CONSOLE_ATTRIBUTE(hConsole, DEFAULT_CONSOLE_ATTRIBUTE);
				}
			}
		}
		DWORD old = 0;
		VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
	}

	if (!WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, NULL)) {
		SendConsoleNote(hConsole, "[-] Can't clear shellcode.\n");
	}
	if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
		SendConsoleNote(hConsole, "[-] Can't release shellcode memory.\n");
	}
	if (!VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
		SendConsoleNote(hConsole, "[-] Can't clear map memory.\n");
	}
	return TRUE;
}

VOID WINAPI Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	IMAGE_NT_HEADERS* pOpt = (IMAGE_NT_HEADERS*)((char*)pBase + ((IMAGE_DOS_HEADER*)pBase)->e_lfanew);
	f_LoadLibraryA _LoadLibraryA = pData->pLoadLibraryA;
	f_GetProcAddress _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	f_DLL_ENTRY_POINT _DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->OptionalHeader.AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->OptionalHeader.ImageBase;
	if (LocationDelta) {
		if (pOpt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			IMAGE_BASE_RELOCATION* pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const IMAGE_BASE_RELOCATION* pRelocEnd = (IMAGE_BASE_RELOCATION*)((uintptr_t)(pRelocData) + pOpt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = (WORD*)(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = (UINT_PTR*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += (UINT_PTR)LocationDelta;
					}
				}
				pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE *)(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		IMAGE_IMPORT_DESCRIPTOR* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = (char*)(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
				}
				else {
					IMAGE_IMPORT_BY_NAME* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		IMAGE_TLS_DIRECTORY* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, NULL);
	}
	BOOL ExceptionSupportFailed = FALSE;

#ifdef _WIN64

	if (pData->SEHSupport) {
		IMAGE_DATA_DIRECTORY excep = pOpt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable((IMAGE_RUNTIME_FUNCTION_ENTRY*)(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = TRUE;
			}
		}
	}

#endif

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = (HINSTANCE)(0x505050);
	else
		pData->hMod = (HINSTANCE)(pBase);
	
}