# Guía de configuración y uso

[Resumen en español](../../README.es.md) · [한국어](../ko/GUIDE.md) · [English](../en/GUIDE.md) · [简体中文](../zh-CN/GUIDE.md)

**Controlador 2.6.0.1 · Kernel Studio 3.2.2 · Windows x64 · ManualV4 ABI v3 / 2104 bytes**

> [!IMPORTANT]
> Use el controlador y el panel actualizados juntos. El panel muestra la **versión cargada** del dispositivo, no la versión del `.sys` en disco. Compilar y cargar el controlador son comprobaciones distintas.

## 1. Preparar y compilar

Use Windows x64, Python de 64 bits, herramientas C++ de Visual Studio 2022 y Windows SDK/WDK compatibles. La validación de desarrollo utilizó Python 3.14.5 y VS 2022 Professional. Las configuraciones ARM64 no demuestran compatibilidad ARM64. La interfaz es coreana; conservamos sus etiquetas para localizar los controles.

Desde Developer PowerShell, en la raíz:

```powershell
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Debug /p:Platform=x64 /p:SignMode=Off
```

Las salidas son `x64\Release\SampleKernel1.sys` y `x64\Debug\SampleKernel1.sys`. `SignMode=Off` genera archivos sin firmar; no hace que Windows los acepte. Use la firma y el despliegue apropiados para su sistema de pruebas. El repositorio fuente no es un instalador certificado.

Antes de sustituir un controlador cargado, cierre los clientes y restaure congelaciones, parches y breakpoints gestionados cuando corresponda. Después siga su procedimiento habitual de actualización. El dispositivo es `\\.\MyDriver`.

## 2. Iniciar Kernel Studio

```powershell
cd kernel_control_panel
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python kernel_studio.py
```

Abra [http://127.0.0.1:8005/](http://127.0.0.1:8005/). `kernel_studio.py` y `server.py` usan **8005** por defecto. `python kernel_studio.py --port 8006` selecciona otro puerto. El servidor solo escucha en loopback; use un worker, ya que la conexión y el estado pertenecen a ese proceso. Detenga el servidor fuente con Ctrl+C.

Para empaquetar, instale PyInstaller en el entorno de compilación y ejecute `tools\build_release.cmd` desde este directorio. La salida va a `dist/3.2.2/KernelStudio` o a un subdirectorio nuevo con fecha/hora si ya existe. Cierre el panel anterior antes de ejecutar el nuevo `KernelStudio.exe`.

> [!NOTE]
> `/api/build` describe el panel en ejecución. `/api/status` informa del controlador conectado. Sustituir archivos no actualiza procesos del panel que siguen abiertos ni el controlador ya cargado.

## 3. Seleccionar, leer y reducir

Abra **대상 프로세스 선택** (seleccionar destino), busque por nombre/PID o introduzca un PID. La selección verifica actividad e identidad de creación. El descubrimiento sondea PID en pasos de cuatro, no enumera todo el sistema. El rango inicial es 4–65,536 y puede ampliarse.

En **메모리 스캔** (escaneo), elija tipo, condición y rango. Ejecute **New**, cambie un valor en su propio programa de pruebas y ejecute **Next** con el nuevo valor o una condición como Increased. **Live** actualiza la vista sin sustituir la referencia de Next.

Lleve resultados a **메모리 편집** (editor), Watch, estructuras o desensamblado. Escribir, congelar, asignar, liberar, cambiar protección y operar hilos cambia el destino real. Revise la vista previa, la lectura de verificación y el estado de recuperación.

> [!TIP]
> Un marcador recuerda una dirección, no la vida de un proceso. Confirme el destino antes de convertir la dirección de ayer en la evidencia de hoy.

## 4. Interpretar ManualV4

Seleccione un destino en **ManualV4**, introduzca una ruta absoluta como `C:\DLLs\Example.dll` y pulse **커널 매핑 요청**. El panel valida la identidad antes de enviar la solicitud. Actualizar la página o los trabajos no vuelve a solicitar un mapeo.

| Resultado | Interpretación |
|---|---|
| `state: mapped` con éxito del kernel validado | Mapeo completo según el contrato actual |
| `failcode` positivo | Rama concreta del fallo en `manual_map_protocol.h` |
| `failmessage` | Detalles API/validación, valores y NTSTATUS observados en esa rama |
| Respuesta ausente / inválida | Indeterminado; diagnóstico `null`, sin reintento automático |

El paquete v3 mide **2104 bytes**. `failcode` está en **1076** y `failmessage[1024]` en **1080**. La entrada se pone a cero; el éxito devuelve código 0 y mensaje vacío. El primer diagnóstico persiste aunque la limpieza cambie el estado final. El mensaje es ASCII/ANSI, termina en NUL y tiene cola de ceros; el exceso se marca `[truncated]`.

Para **119**, revise sección/RVA, dirección/tamaño/protección solicitados y estado de `ZwProtectVirtualMemory`. Los campos previos incluyen:

- `pre_page`: estado, tipo, protecciones y cobertura de la primera región sobre el rango redondeado.
- `pre_dynamic`: flags de código dinámico y bits decodificados.
- `pre_protection`: nivel, tipo, audit y signer de protección.

> [!IMPORTANT]
> Las nuevas consultas de política/páginas son de solo lectura: no alteran argumentos ni políticas. `UNAVAILABLE` significa que no se pudo validar el resultado. La primera región puede no cubrir toda la solicitud, y la observación no es atómica.

> [!WARNING]
> HTTP 200, consultar un trabajo o transportar el IOCTL no confirma el mapeo. Revise estado validado, NTSTATUS y diagnóstico. `ACCESS_DENIED` es el estado recibido, no una causa interna demostrada. Los campos de salida de una API fallida pueden conservar sus valores iniciales.

Detalles API/ABI: [referencia](../reference/API_ABI.md). Funciones actuales en coreano: [guía del panel](../../kernel_control_panel/README_ko.md).

## 5. Datos, símbolos y límites

La aplicación empaquetada guarda assets, symbols, workspaces y dumps bajo `data/` junto al ejecutable. `KERNEL_STUDIO_DATA_DIR` cambia esa raíz. La ejecución fuente conserva sus ubicaciones; los datos anteriores no se copian automáticamente al nuevo paquete.

El análisis PDB utiliza `native/pdb_symbols.exe` y Microsoft DIA x64. Compile el auxiliar con `native/build_pdb_symbols.cmd`; sus rutas iniciales son de VS 2022 Professional. Ajuste las rutas de compilación para otra instalación y use `KERNEL_STUDIO_DIA_DLL` para otra ubicación de DIA. GUID/Age del PDB deben coincidir con la imagen.

Las transferencias normales se limitan a 1MiB, con lecturas del controlador de hasta 4KiB. Los volcados de rangos pueden alcanzar 16GiB y se escriben en disco. Los huecos con ceros quedan en el manifiesto y no son bytes originales. Las imágenes conservan RVA, no reconstruyen PE en disco. Cancelar espera a la petición actual; reanudar verifica identidad e integridad parcial en la misma sesión del servidor.

## 6. Pruebas y resolución de problemas

Desde la raíz, genere el fixture sintético y ejecute las pruebas:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1
cd kernel_control_panel
python -m unittest discover -p 'test*.py' -v
node test_manual_v4_ui.js
python native/manual_map/run_selftest.py
```

El discovery completo necesita fixture y auxiliar DIA. El harness nativo usa el mapeador actual con DDIs simuladas; no abre un controlador o destino real. `test_driver_readonly.py` permite siete diagnósticos de solo lectura contra un controlador cargado; `test_driver_all_ioctl.py` tiene el mismo alcance, no una suite real completa. Véanse [fixture](../../samples/README.md) y [validación](../VALIDATION.md).

| Síntoma | Comprobar |
|---|---|
| No conecta al dispositivo | Servicio cargado, firma aceptada, administrador y `\\.\MyDriver` |
| Panel antiguo | Ejecutable/directorio fuente activo, `/api/build`, luego recargar navegador |
| Proceso ausente | Ampliar rango o introducir PID |
| Paquete ManualV4 incompatible | Controlador/panel actualizados, ABI v3 / 2104 bytes |
| Mapeo denegado | NTSTATUS, failcode, failmessage y observaciones previas válidas |
| `pre_*: UNAVAILABLE` | Estado, longitud y validación; no asumir política cero |
| PDB no disponible | Auxiliar, DIA, GUID/Age y ruta del runtime |

Use reproducciones sintéticas en incidencias públicas, sin volcados privados ni DLL/PDB de usuarios. La licencia se explica en [LICENSE_STATUS.md](../../LICENSE_STATUS.md).
