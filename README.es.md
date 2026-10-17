<div align="center">

# Kernel Based Process Memory Editor

**SampleKernel1 · Kernel Studio**<br>
Un espacio local para la memoria de procesos Windows, con un controlador de kernel.

![Driver 2.6.0.2](https://img.shields.io/badge/Driver-2.6.0.2-2563eb)
![Panel 3.2.3](https://img.shields.io/badge/Kernel_Studio-3.2.3-7c3aed)
![Manual ABI v3 2104 bytes](https://img.shields.io/badge/Manual_ABI-v3_%C2%B7_2104_bytes-0f766e)
![Windows x64](https://img.shields.io/badge/Platform-Windows_x64-334155)

[한국어](README.md) · [English](README.en.md) · [简体中文](README.zh-CN.md) · **Español**

![Arquitectura: navegador, panel local, puente IOCTL y controlador](docs/images/project-overview.svg)

[Inicio rápido](#inicio-rápido) · [Funciones por navegación](#features) · [Guía](docs/es/GUIDE.md) · [API / ABI](docs/reference/API_ABI.md)

</div>

> [!IMPORTANT]
> Esta actualización combina **controlador 2.6.0.2** y **panel 3.2.3**. ManualV4 usa el **paquete v3 de 2104 bytes**; los clientes v1/v2 son incompatibles. Compilar un `.sys` no sustituye al controlador que Windows ya tiene cargado.

<a id="features"></a>

## Funciones, una navegación a la vez

La lista sigue el orden de la barra lateral. Las etiquetas coreanas entre paréntesis coinciden con la interfaz.

| Navegación | Función |
|---|---|
| **대시보드 (Panel)** | Consulte la conexión del controlador, el objetivo seleccionado y el estado reciente. |
| **구조체 / 클래스 (Estructuras / clases)** | Defina y examine campos y offsets de diseños de memoria propios. |
| **프로젝트 작업 공간 (Espacio de proyectos)** | Guarde y recupere ajustes, direcciones y estado de búsqueda como proyectos. |
| **변경 기록 / 묶음 (Registro / grupos de cambios)** | Agrupe cambios, añada notas y revíselos más tarde. |
| **변화 타임라인 (Línea temporal)** | Registre valores y bytes a lo largo del tiempo y compare dos muestras. |
| **프로세스 / 권한 (Procesos / acceso)** | Consulte procesos, tokens, handles e hilos relacionados. |
| **EPROCESS 구조체 (Estructura EPROCESS)** | Explore campos del objeto de proceso del kernel con diseños por versión. |
| **메모리 편집 (Editor de memoria)** | Lea y edite direcciones con valores tipados o bytes individuales. |
| **읽기 / 쓰기 / 덤프 (Lectura / escritura / volcado)** | Envíe solicitudes de memoria sin formato y vuelque bytes de un rango. |
| **메모리 할당 (Asignación de memoria)** | Asigne una región en el proceso elegido y consulte su dirección. |
| **메모리 관리 (Gestión de memoria)** | Gestione asignación, liberación, protección, copia, relleno y snapshots. |
| **메모리 스캔 (Escaneo)** | Reduzca direcciones candidatas con búsquedas de valores, patrones, AOB y cadenas. |
| **Watch / 값 고정 (Watch / congelación)** | Siga direcciones y congele o libere sus valores. |
| **모듈 / PE / 주소 (Módulos / PE / direcciones)** | Examine módulos, regiones, secciones PE, imports, exports y pertenencia. |
| **메모리 / 이미지 덤프 (Volcados de memoria / imagen)** | Revise el progreso y los resultados de volcados de rangos e imágenes. |
| **메모리 맵 변화 (Cambios del mapa)** | Guarde mapas de regiones de memoria y compare muestras. |
| **스레드 / 레지스터 (Hilos / registros)** | Consulte hilos y registros generales; gestione contexto y prioridad. |
| **APC_NORMALIZE** | Solicite un User APC para el hilo elegido con contexto y dos argumentos del sistema. |
| **하드웨어 중단점 (Puntos de interrupción hardware)** | Configure, consulte y elimine puntos hardware por hilo. |
| **스냅샷 / 패치 / 분석 (Snapshots / parches / análisis)** | Compare o restaure snapshots, previsualice/aplique/deshaga parches y analice punteros o estructuras. |
| **디스어셈블리 (Desensamblado)** | Muestre instrucciones x86/x64 de memoria e inspeccione el flujo de control. |
| **DLL / 이미지 함수 (DLL / funciones de imagen)** | Relacione exports y símbolos PDB con direcciones y detalles de funciones. |
| **ManualV4** | Elija un DLL con el selector nativo de Windows; envíe su ruta absoluta al kernel y, si quiere, omita DllMain. |
| **ManualV4_Viewer** | Valide la base de un mapeo correcto y examine direcciones y parámetros PDB. |
| **ObRegisterCallback Panel** | Consulte, registre y elimine el Object Callback global del controlador. |
| **작업 큐 / 시나리오 (Cola / escenarios)** | Encole escenarios JSON y solicitudes agrupadas y consulte su progreso. |
| **호출 이력 / 기능 (Historial / capacidades)** | Revise el estado del controlador y los resultados de llamadas seguidas. |
| **메모리 Wide View (Beta) (Vista amplia de memoria)** | Explore el mapa, los bytes cercanos y los cambios observados en una vista amplia. |

> [!TIP]
> «Seguramente es la dirección correcta» es una estrategia valiente. Revise los bytes y el proceso primero: su yo de mañana ya tendrá suficientes pestañas abiertas.

## El recorrido de una solicitud

```mermaid
flowchart LR
    UI["Navegador · interfaz coreana"] --> API["FastAPI · 127.0.0.1:8005"]
    API --> Bridge["KernelOnlyBridge · ctypes"]
    Bridge --> IO["DeviceIoControl · 44 contratos"]
    IO --> Driver["SampleKernel1.sys"]
    Driver --> Target["Memoria del proceso"]
    API --> Store["SQLite · JSON · volcados"]
```

Las lecturas, escrituras y consultas de regiones pasan por el controlador. En modo usuario se comparan bytes devueltos, gestionan candidatos y analizan PE/instrucciones. La conexión al dispositivo usa `CreateFileW`, `DeviceIoControl` y `CloseHandle`.

Los **44 contratos** abarcan `0x800`–`0x829`, ManualV4 `0x878` y APC_NORMALIZE `0x900`. El inventario completo está en la [referencia API / ABI](docs/reference/API_ABI.md), sin exigir una maratón de desplazamiento en la portada.

## Una vista del espacio de trabajo

| Editor de memoria | Escaneo de memoria |
|---|---|
| ![Interfaz histórica del editor](docs/images/02-memory-editor.jpg) | ![Interfaz histórica del escaneo](docs/images/03-memory-scan.jpg) |

*Capturas históricas del 2026-10-05–06, tomadas antes de elegir un proceso. Son referencias de la interfaz, no una vista completa de la navegación o de las validaciones actuales. Consulte la [procedencia de las imágenes](docs/images/README.md).*

## Inicio rápido

Use Windows x64, **Python de 64 bits**, herramientas C++ de Visual Studio 2022 y Windows SDK/WDK compatibles para compilar el controlador. La validación de desarrollo utilizó Python 3.14.5. [requirements.txt](kernel_control_panel/requirements.txt) establece rangos de dependencias, no un archivo de versiones bloqueadas.

Desde Developer PowerShell, en la raíz del repositorio:

```powershell
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
```

La salida es `x64\Release\SampleKernel1.sys`. Este comando crea un controlador **sin firmar**; instalarlo/cargarlo requiere una configuración de firma y despliegue aceptada por su sistema de pruebas. Se entrega código fuente, no un instalador certificado WHQL. Véase la [guía](docs/es/GUIDE.md).

Inicie el panel desde el código fuente:

```powershell
cd kernel_control_panel
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python kernel_studio.py
```

Abra **[http://127.0.0.1:8005/](http://127.0.0.1:8005/)**. `python server.py` usa el mismo puerto por defecto; `python kernel_studio.py --port 8006` permite otro. Ejecute un solo worker.

1. Compruebe la versión del **controlador cargado** en el panel.
2. Abra **대상 프로세스 선택** y elija su proceso de pruebas.
3. Lea una dirección conocida o busque un valor con New / Next.
4. Examine el resultado antes de escribir, congelar valores o modificar hilos.

> [!NOTE]
> La búsqueda de procesos sondea rangos PID con el contrato de consulta del kernel. No es una enumeración completa del sistema. Amplíe el rango o introduzca un PID si falta el proceso.

Para empaquetar el panel, active el entorno de compilación, instale PyInstaller y ejecute `tools\build_release.cmd` dentro de `kernel_control_panel`. Usa una carpeta nueva `dist/3.2.3/KernelStudio`, o un subdirectorio con fecha/hora si la versión ya existe, conservando paquetes y datos anteriores.

## Compilar, probar y entender la evidencia

Las últimas comprobaciones de desarrollo registraron **561 pruebas Python**, **8 grupos UI** y **2009 comprobaciones nativas en 135 ubicaciones de fallo**, además de compilaciones x64 Release/Debug y del panel. Son resultados de compilación/regresión, no prueba de todas las operaciones contra destinos reales en todas las versiones de Windows.

```powershell
# Desde la raíz: fixture de pruebas PE / PDB
powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1
cd kernel_control_panel
python -m unittest discover -p 'test*.py' -v
node test_manual_v4_ui.js
python native/manual_map/run_selftest.py
```

El harness nativo compila el **cuerpo actual del mapeador** con DDIs simuladas y solo adapta includes. No abre un controlador ni mapea un DLL en un proceso real. El discovery Python completo necesita el fixture DLL/PDB y el auxiliar DIA; véanse [samples](samples/README.md) y el [alcance de validación](docs/VALIDATION.md).

`test_driver_readonly.py` y `test_driver_all_ioctl.py` ejecutan los mismos siete diagnósticos de solo lectura al usarse explícitamente con un controlador cargado; el nombre del segundo no demuestra pruebas reales de las 43 operaciones.

## Límites prácticos

- x64 es el destino de desarrollo; las configuraciones ARM64 no garantizan compatibilidad.
- Varias lecturas de un proceso cambiante no forman una instantánea atómica.
- Los volcados de imágenes mapeadas conservan RVA; no reconstruyen archivos PE ejecutables en disco.
- Las escrituras, congelaciones, protecciones y operaciones de hilos cambian el estado real del destino.
- El panel fuente y el empaquetado usan raíces de datos distintas; véase la [guía](docs/es/GUIDE.md).

## Más detalles, menos búsqueda

| Documento | Contenido |
|---|---|
| [Guía de configuración y uso](docs/es/GUIDE.md) | Compilar, iniciar, seleccionar y resolver problemas |
| [API / ABI](docs/reference/API_ABI.md) | Contratos y formatos de paquetes |
| [Guía fuente del panel](kernel_control_panel/README_ko.md) | Funciones actuales en detalle, en coreano |
| [Workbench DLL](kernel_control_panel/DLL_WORKBENCH.md) | Imágenes, símbolos y llamadas |
| [Validación](docs/VALIDATION.md) | Evidencia de pruebas y límites |
| [Fixture](samples/README.md) | Reconstruir entradas DLL/PDB sintéticas |
| [Contribuciones](CONTRIBUTING.md) / [Seguridad](SECURITY.md) | Informes y flujo del repositorio |
| [Estado de licencia](LICENSE_STATUS.md) | No se asigna una licencia por cuenta del propietario |

Git no necesita paquetes generados del controlador/panel, volcados de usuarios, DLL/PDB subidos ni certificados de firma. Los binarios se generan localmente; aquí se conservan fuentes y soporte reproducible.
