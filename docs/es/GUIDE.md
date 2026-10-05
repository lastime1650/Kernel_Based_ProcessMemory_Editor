# Guía de instalación y uso

[Introducción en español](../../README.es.md) · [한국어](../ko/GUIDE.md) · [English](../en/GUIDE.md) · [简体中文](../zh-CN/GUIDE.md)

## Arquitectura y requisitos

La ruta activa es navegador → FastAPI → `KernelOnlyBridge` → `DeviceIoControl` → `SampleKernel1.sys`. El dispositivo es `\\.\MyDriver`. Python conecta mediante `CreateFileW`, `DeviceIoControl` y `CloseHandle`. Las lecturas, búsquedas y mapas del destino pasan por el kernel; NumPy, PE e instrucciones se analizan en modo usuario sobre los bytes recibidos. `memory_scanner.py` conserva un escáner Win32 antiguo que el servidor actual no utiliza para acceder al destino.

- Windows x64, Python de 64 bits, herramientas C++ y Windows SDK/WDK compatibles.
- Entorno verificado: Python 3.14.5, Visual Studio 2022 Professional, SDK 10.0.26100.0 y WDK 10.0.26100.6584.
- Dependencias originales: FastAPI, Uvicorn, psutil, Capstone 5, Keystone 0.9.2 y NumPy. Se conservan los rangos; no hay archivo de bloqueo reproducible.
- La solución declara ARM64, pero los contextos y llamadas remotas dependen de x64. ARM64 no está verificado.
- La interfaz sigue en coreano; los nombres coreanos siguientes permiten identificar los controles.

## Compilación y carga del controlador

Prepare Visual Studio/SDK/WDK siguiendo las [instrucciones de Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk). Ejecute los comandos en Developer PowerShell desde la raíz. Se verificó el entorno indicado, no todas las combinaciones de herramientas.

```powershell
msbuild SampleKernel1.sln /m /p:Configuration=Release /p:Platform=x64
msbuild SampleKernel1.sln /m /p:Configuration=Debug /p:Platform=x64
```

```powershell
sc.exe create SampleKernel1 type= kernel start= demand binPath= "C:\Kernel_Based_ProcessMemory_Editor\x64\Release\SampleKernel1.sys"
sc.exe start SampleKernel1
sc.exe query SampleKernel1
```


El ejemplo `sc.exe` registra un servicio manual para un **controlador correctamente firmado que el sistema de prueba permite cargar**. Use un terminal de administrador y sustituya la ruta. Si el servicio existe, revise `sc.exe qc SampleKernel1` antes de modificarlo. Siga la [documentación de firma](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing). No se incluyen certificados ni scripts para cambiar protecciones del sistema.

El INF original contiene valores de plantilla para fabricante, ID de hardware y DriverVer. Una distribución pública requiere configurarlos en su copia, validar y firmar el paquete. No es un instalador INF terminado. Antes de reemplazar el controlador, cierre servidor/clientes y restaure parches, congelaciones y puntos de interrupción según corresponda. Ejecute `sc.exe stop SampleKernel1`, prepare el nuevo archivo y vuelva a iniciar. Use `sc.exe delete SampleKernel1` solo para eliminar el servicio. Liberar seguimiento o descargar el controlador no termina un hilo de función ya creado.

Auxiliar PDB opcional: ejecute `build_pdb_symbols.cmd` en `kernel_control_panel/native`. El script y `Symbols.dia` de `image_workbench.py` fijan rutas de VS 2022 Professional. Ajuste ambas en su copia si la instalación difiere. Los símbolos requieren que GUID y Age de CodeView coincidan con la imagen.

## Ejecutar el servidor

Siga los [comandos del entorno virtual](../../README.es.md#inicio-rápido) y abra la [interfaz en 8005](http://127.0.0.1:8005/). Los originales `python server.py` y el archivo por lotes usan 8000; esta guía usa Uvicorn `--port 8005`. Ejecute un solo worker, ya que cada uno tiene conexiones y estado independientes. Detenga el servidor con Ctrl+C.

## 1. Conexión y selección del destino

![Panel](../images/01-dashboard.jpg)

Compruebe conexión y versión. Abra **대상 프로세스 선택** (seleccionar destino), busque nombre/PID o introdúzcalo. Se verifica actividad e identidad de creación. Al no existir un IOCTL de enumeración completa, se consultan PID de cuatro en cuatro. El rango predeterminado es 4–65,536; amplíelo a 262,144 o 1,048,576 o introduzca otro PID manualmente. La lista no garantiza cobertura completa.

Cambiar o volver a seleccionar el destino puede limpiar entradas y sesiones, pero no restaura cambios aplicados. Restaure los cambios necesarios antes de cambiar.

## 2. Buscar y reducir candidatos

![Escaneo](../images/03-memory-scan.jpg)

En **메모리 스캔** elija tipo, condición y valor y ejecute **New**. Por ejemplo, busque el entero de 32 bits 100 en su propio programa de prueba, cámbielo a 101 desde ese programa y ejecute **Next** con 101 o Increased. Unknown inicia búsquedas numéricas/de estructuras sin valor conocido. **Rescan** actualiza la referencia sin reducir candidatos legibles. La actualización Live no cambia la referencia de Next.

Se admiten números con/sin signo, UTF-8/UTF-16LE, AOB como `DE AD ?? A? ?F` y estructuras con campos numéricos. Direcciones y enteros de 64 bits permanecen como cadenas. Alineación 1 incluye valores no alineados; inicio inclusivo y fin exclusivo. Guarde candidatos o envíelos a Hex, desensamblado o estructuras.

El espacio nuevo guarda candidatos en SQLite y no se detiene en el límite antiguo de 50,000. Presupuesto inicial 256MiB, máximo 4GiB; informa búsquedas parciales y errores. Las páginas admiten 50/100/200/500 filas y se guardan hasta 256 direcciones por sesión. Distinga filtro/orden de página actual frente a todos los candidatos; CSV completo se genera como trabajo de exportación. Las API antiguas mantienen su límite separado de 50,000.

## 3. Edición, Watch, estructuras y asignación

![Editor](../images/02-memory-editor.jpg)

En **메모리 편집**, abra una dirección hexadecimal y edite bytes/números con doble clic o por tipo. Ctrl+→ despliega punteros; Ctrl+← los contrae; la rueda recorre direcciones adyacentes. Restaurar ediciones verifica los bytes actuales. **Watch / 값 고정** y Freeze escriben repetidamente y se detienen ante fallo, salida o reutilización de PID.

**구조체 / 클래스** define campos, matrices, estructuras anidadas y punteros. Los conjuntos de cambios siguen vista previa → comprobar original → aplicar → verificar lectura. **프로젝트 작업 공간** guarda vistas y localizadores para reconectar; **변경 기록 / 묶음** gestiona registros de recuperación; **변화 타임라인** compara muestras, sin registrar todos los cambios intermedios.

**메모리 할당** recibe cadenas ANSI/UTF-16LE con NULL final o bytes de archivo, calcula el tamaño y asigna memoria de lectura/escritura. Escribe y verifica mediante el kernel; máximo 1MiB incluido NULL. Libera usando BaseAddress registrado. Limpiar historial no libera la memoria. **메모리 관리** cambia protección, copia y rellena. Wide View es Beta. Escribir, liberar, congelar y restaurar cambian realmente la memoria del destino.

## 4. Volcados, módulos y funciones

**메모리 / 이미지 덤프** admite range/image/images. El rango máximo es 16GiB; salida en `dumps/` o `KERNEL_STUDIO_DUMP_DIR`. Cancelar espera la petición actual y conserva `.part`; continuar en la misma sesión comprueba identidad, longitud y hash. Los registros de descargas terminadas sobreviven al reinicio, los trabajos activos no. La política Zero documenta los tramos ilegibles rellenados con cero: esos ceros no son datos originales.

Los volcados de imagen usan disposición RVA: desplazamiento de archivo = VA − base. No reconstruyen un PE ejecutable de disco. **모듈 / PE / 주소** muestra módulos, encabezados, secciones, importaciones/IAT, exportaciones y pertenencia de direcciones. Fuera de MEM_IMAGE comprueba encabezados válidos al inicio de regiones comprometidas, no todos sus bytes.

En **DLL / 이미지 함수**, seleccione una imagen y analice funciones. Confirme la DLL en la lista de módulos aunque la solicitud de carga indique éxito. PDB es opcional; sin símbolos pueden faltar funciones o inferirse tipos. Las llamadas requieren controlador 2.2+, destino x64, un argumento entero/puntero de 64 bits y salida de 32 bits. Consulte el CallId existente tras un tiempo de espera; no repita automáticamente la creación. Liberar seguimiento no termina el hilo ni descarga la DLL.

## 5. Código, hilos y puntos de interrupción

![Desensamblado](../images/04-disassembly.jpg)

En **디스어셈블리**, indique dirección, tamaño y x86/x64. Haga doble clic en ASM/Graph, valide una línea Intel y déjela pendiente. Se rechazan codificaciones más largas; las cortas se rellenan con NOP. Solo **편집 적용** aplica los bytes. Undo/Redo de dirección navega; Undo/Redo de parche escribe. La recuperación exige bytes actuales esperados. El pseudocódigo no garantiza código original ni C compilable.

Los parches no son atómicos frente a hilos ejecutándose y no sincronizan la caché de instrucciones. Aplíquelos en una prueba controlada mientras ese código no se ejecuta. **스레드 / 레지스터** comprueba PID/TID/creación, suspende temporalmente, edita los campos pedidos, verifica y restaura el contador de suspensión. La ABI incluye 18 campos generales, sin XMM/YMM. Los puntos de interrupción admiten ejecución/escritura/lectura-escritura y longitudes 1/2/4/8; conservan recuperación si falla la eliminación.

## API y límites

`/docs` ofrece Swagger, `/redoc` ReDoc y `/openapi.json` el esquema. Sustituya PID/direcciones del ejemplo por datos reales de su destino autorizado.

```powershell
Invoke-RestMethod http://127.0.0.1:8005/api/status
Invoke-RestMethod http://127.0.0.1:8005/api/studio/capabilities
$requestBody = '{"operation":"read","args":{"pid":1234,"address":"0x140000000","size":64}}'
Invoke-RestMethod http://127.0.0.1:8005/api/studio/execute -Method Post -ContentType application/json -Body $requestBody
```

Verifique `success`, `result_status` y `driver_response`; HTTP 200 no basta. Consulte el [inventario API/ABI](../reference/API_ABI.md). Use job ID para consultar volcados/búsquedas y espere que termine la cancelación.

Límites: transferencia normal 1MiB, lectura del kernel por partes de 4KiB, tablas normales 5,000, mapas internos 50,000, nodos del kernel 65,536, hilos 64 y handles 128. Se rechazan mapas truncados cuando la operación exige cobertura completa. Instantáneas (16), mapas (8) y parches (64) pertenecen a la sesión. Proyectos, diarios, PDB, DLL y volcados se guardan en disco; marcadores en el navegador. Las lecturas secuenciales de procesos activos no son instantáneas atómicas.

## Diagnóstico y pruebas

| Síntoma | Comprobar |
|---|---|
| No abre el dispositivo | Administrador, servicio, firma/carga y `\\.\MyDriver` |
| Dirección inválida | Identidad, rango de usuario, Guard/NoAccess, salida o reutilización PID |
| Falta un proceso | Ampliar rango o introducir PID; la enumeración es incompleta |
| No conecta a 8005 | Puerto/errores Uvicorn; los lanzadores originales usan 8000 |
| Interfaz antigua | Actualizar, caché y directorio real del servidor activo |
| PDB falla | DIA SDK, compilación/ruta y GUID/Age |
| Búsqueda parcial/cuota | Reducir rango, New; revisar presupuesto, límites y errores |

Tres regresiones comprueban la existencia del auxiliar DIA; compílelo con `native/build_pdb_symbols.cmd` antes de ejecutar todas. CI enlaza la instalación real de VS 2022 en Windows 2022 a la ruta Professional original y compila el auxiliar. Configura el ejecutor temporal sin editar código.

```powershell
cd kernel_control_panel
python -m unittest discover -p 'test*.py' -v
python test_driver_readonly.py
```

El primer comando ejecuta regresiones simuladas. El segundo realiza siete consultas de solo lectura sobre el propio proceso de diagnóstico mediante el controlador cargado. `test_driver_all_ioctl.py` usa el mismo diagnóstico, no prueba todas las modificaciones reales. Consulte el [alcance de validación](../VALIDATION.md). Use datos sintéticos en incidencias públicas, sin volcados, PDB privados ni contenido real de memoria.
