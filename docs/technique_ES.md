# Antes que nada , debemos saber lo siguiente

1. **Trabajaremos con archivos PE de Windows**
2. **Hablaremos de MS-DOS y DOS**:
   - MS-DOS, o Microsoft Disk Operating System, fue un sistema operativo desarrollado por Microsoft para computadoras personales ([Wikipedia](https://es.wikipedia.org/wiki/MS-DOS))
3. **Hablaremos de Arquitecturas de 32 y 64 bits**
_________________________________________________________________________________________________________

Portable Executable (PE) es un formato de archivo para archivos ejecutables, de código objeto, bibliotecas de enlace dinámico (DLL), archivos de fuentes FON​ y otros usados en versiones de 32 bit y 64 bit del sistema operativo Microsoft Windows segun Wikipedia.

Estos archivos contienen una estructura que deberemos entender para esta tecnica:

![image](https://github.com/user-attachments/assets/6bff7db8-1895-432d-8915-8d0be11a8608)

Solo mencionaremos las partes que son necesarias

## Dos Header
Este encabezado es una estructura de 64 bits que existe al principio de todos los PE Files, este no es importante en sistemas Windows modernos pero se sigue incluyendo por razones de compatibilidad con versiones anteriores.

Esta cabecera convierte el archivo en un ejecutable MS-DOS, de modo que cuando se carga en MS-DOS se ejecuta el stub DOS en lugar del programa real.

Sin esta cabecera, si se intenta cargar el ejecutable en MS-DOS no se cargará y sólo producirá un error genérico.

### Estructura
![image](https://github.com/user-attachments/assets/4eb708c2-d37d-4e26-979a-bc24c1c5172c)

Esta estructura es importante para el cargador PE en MS-DOS, sin embargo sólo unos pocos miembros de la misma son importantes para el cargador PE en sistemas Windows, por lo que no vamos a ver todo , sólo los miembros importantes de la estructura.

* e_magic: Es el primer miembro de la Cabecera DOS, es un WORD por lo que ocupa 2 bytes, se le suele llamar número mágico. Tiene un valor fijo de 0x5A4D o MZ en ASCII, y sirve como firma que marca el fichero como ejecutable MS-DOS.
* e_lfanew: Este es el último miembro de la estructura de cabecera del DOS, se encuentra en el offset 0x3C dentro de la cabecera del DOS y contiene un offset al inicio de las cabeceras NT. Este miembro es importante para el cargador PE en sistemas Windows porque le dice al cargador dónde buscar la cabecera del archivo.

![image](https://github.com/user-attachments/assets/669dcc0d-c8ef-4114-87a0-ea86c9c902b3)

Como puedes ver, el primer miembro de la cabecera es el número mágico con el valor fijo del que hablamos que era 5A4D.

El último miembro de la cabecera (en el offset 0x3C) recibe el nombre de «File address of new exe header», tiene el valor 100, podemos seguir hasta ese offset y encontraremos el inicio de las cabeceras NT como era de esperar:

## Dos Stub
El stub de DOS es un programa de MS-DOS que imprime un mensaje de error diciendo que el ejecutable no es compatible con DOS y luego sale.

Esto es lo que se ejecuta cuando el programa se carga en MS-DOS, el mensaje de error por defecto es «Este programa no puede ejecutarse en modo DOS», sin embargo este mensaje puede ser cambiado por el usuario durante el tiempo de compilación.

Eso es todo lo que necesitamos saber sobre el stub DOS, realmente no nos importa, pero puede hacer mucho mas.

![image](https://github.com/user-attachments/assets/d150b7bc-2e5c-4962-8b66-c38b3404cc00)

## NT Header
Los NT-Headers son una parte importante de los ejecutables portables. Contienen una gran cantidad de información sobre el PE File.

Existen dos versiones de la estructura dependiendo de la arquitectura (32 bits o 64 bits). En cualquier caso, la estructura tiene tres elementos: una firma, un encabezado de archivo (IMAGE_FILE_HEADER) y un encabezado opcional (IMAGE_OPTIONAL_HEADER).

Contienen muchisima informacion relevante para otras areas, pero no para esta, solo nos centraremos en algunas partes del encabezado opcional.

Precisamente en el Entrypoint y ImageBase :
   - Entrypoint: Muy basicamente es la dirección de memoria donde comienza la ejecución del código cuando se inicia un programa
   - ImageBase: Es la dirección de memoria virtual donde se carga un archivo ejecutable cuando se ejecuta

_________________________________________________________________________________________________________

## 1. Obtenemos los bytes del archivo a inyectar y los guardamos en un buffer

``` cpp
    HANDLE sourceFile = CreateFileA(sourceProcess.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (sourceFile == INVALID_HANDLE_VALUE) {
        ErrorExit("No se pudo abrir el archivo de origen");
    }

    DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
    LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), 0, sourceFileSize);
```

Donde usamos [CreateFileA](https://learn.microsoft.com/es-es/windows/win32/api/fileapi/nf-fileapi-createfilea) para abrir un [Handle](https://es.wikipedia.org/wiki/Handle) al archivo.

Luego deberemos obtener su peso utilizando la funcion [GetFileSize](https://learn.microsoft.com/es-es/windows/win32/api/fileapi/nf-fileapi-getfilesize)

Por ultimo, asignamos memoria utilizando [HeapAlloc](https://learn.microsoft.com/es-es/windows/win32/api/heapapi/nf-heapapi-heapalloc) para guardar los bytes del archivo

## 2. Obtener los encabezados del archivo

``` cpp
    PIMAGE_DOS_HEADER sourceImageDOSHeader = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
    PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)sourceFileBytesBuffer + sourceImageDOSHeader->e_lfanew);
```

Donde obtendremos el Entrypoint y el Imagebase , necesarios para la ejecucion del archivo

## 3. Crear proceso y iniciarlo en estado suspendido

``` cpp
    STARTUPINFOA startupInfo;                  // Guardaremos el StartupInfo del proceso
    PROCESS_INFORMATION processInfo;           // Guardaremos el ProcessInformation del proceso
```

Se inicializan las estructuras STARTUPINFOA y PROCESS_INFORMATION rellenándolas con ceros utilizando [ZeroMemory](https://learn.microsoft.com/es-es/previous-versions/windows/desktop/legacy/aa366920(v=vs.85))
``` cpp
    ZeroMemory(&startupInfo, sizeof(startupInfo));   
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);
```

Utilizamos [CreateProcessA](https://learn.microsoft.com/es-es/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) para iniciar nuestro proceso en estado SUSPENDIDO

Es necesario que ejecutemos el proceso en estado suspendido, esto sigifica que proceso se inicia pero no ejecuta código

``` cpp
    if (!CreateProcessA(
        targetProcess.c_str(),    // Nombre del proceso a crear
        NULL,                      // Parámetros de línea de comandos
        NULL,                      // Atributos de seguridad del proceso
        NULL,                      // Atributos de seguridad del hilo
        FALSE,                     // Herencia de handles
        CREATE_SUSPENDED,          // Flags de creación - SUSPENDIDO
        NULL,                      // Entorno del proceso
        NULL,                      // Directorio actual
        &startupInfo,              // Información de inicio
        &processInfo               // Información del proceso
    )) {
        ErrorExit("No se pudo crear el proceso legítimo");
    }

```
