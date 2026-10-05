#include "helper.hpp"
#include "remote_call.hpp"
#include "ioctl_helper.hpp"

//
// Track the control device created by this driver for safe destruction
//
static PDEVICE_OBJECT g_ControlDeviceObject = nullptr;

extern "C" DRIVER_INITIALIZE DriverEntry;

DRIVER_UNLOAD DriverUnloadRoutine;

VOID DriverUnloadRoutine(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    //
    // 1. Drain active requests and deferred DLL cleanup
    //
    helper::lifecycle::Shutdown();
    helper::remote_call::Shutdown();
    helper::process::ReapDllCleanup(TRUE);

    //
    // 2. Unregister device objects and symbolic links
    //
    PDEVICE_OBJECT device = g_ControlDeviceObject;
    g_ControlDeviceObject = nullptr;
    helper::ioctl::UnregisterIoctlRoutine(device, L"\\DosDevices\\MyDriver");
}

extern "C"
NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // Record driver load start time for diagnostics telemetry
    helper::diagnostics::RecordDriverStart();

    // Initialize request rundown, user-function call tracking and DLL cleanup
    helper::lifecycle::Initialize();
    helper::remote_call::Initialize();
    helper::process::InitializeDllCleanup();

    // A normal load uses its owning driver object. Keep the dynamic path
    // for callers that do not supply one, with the same device/IOCTL ABI.
    PDRIVER_OBJECT target_driver = DriverObject;
    if (target_driver == nullptr)
    {
        NTSTATUS status = helper::driver::CreateDriver(L"\\Driver\\MyDriver2", &target_driver);
        if (!NT_SUCCESS(status)) return status;
    }

    if (target_driver != nullptr)
    {
        target_driver->DriverUnload = DriverUnloadRoutine;
        target_driver->MajorFunction[IRP_MJ_CREATE] = helper::remote_call::FileRoutine;
        target_driver->MajorFunction[IRP_MJ_CLEANUP] = helper::remote_call::FileRoutine;
        target_driver->MajorFunction[IRP_MJ_CLOSE] = helper::remote_call::FileRoutine;
        target_driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = helper::ioctl_helper::DeviceControlRoutine;
    }
    else
    {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = helper::ioctl::RegisterIoctlRoutine(
        target_driver,
        L"\\Device\\MyDriver",
        L"\\DosDevices\\MyDriver",
        &g_ControlDeviceObject
    );
    if (!NT_SUCCESS(status))
    {
        if (DriverObject == nullptr) IoDeleteDriver(target_driver);
        g_ControlDeviceObject = nullptr;
    }
    return status;
}
