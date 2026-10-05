#include "helper.hpp"


#define IOCTL_TEST \
    CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x800, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS \
    )


NTSTATUS IoctlRoutine(
    _In_ PDEVICE_OBJECT device_object,
    _Inout_ PIRP irp
)
{
    UNREFERENCED_PARAMETER(
        device_object
    );


    PIO_STACK_LOCATION stack =
        IoGetCurrentIrpStackLocation(
            irp
        );


    NTSTATUS status =
        STATUS_INVALID_DEVICE_REQUEST;

    ULONG_PTR information =
        0;


    switch (
        stack->Parameters.DeviceIoControl.IoControlCode
        )
    {
    case IOCTL_TEST:
    {
        //
        // METHOD_BUFFERED:
        //
        // Input / Output:
        // irp->AssociatedIrp.SystemBuffer
        //

        PVOID buffer =
            irp->AssociatedIrp.SystemBuffer;

        ULONG input_size =
            stack->Parameters.DeviceIoControl
            .InputBufferLength;

        ULONG output_size =
            stack->Parameters.DeviceIoControl
            .OutputBufferLength;


        UNREFERENCED_PARAMETER(
            buffer
        );

        UNREFERENCED_PARAMETER(
            input_size
        );

        UNREFERENCED_PARAMETER(
            output_size
        );


        status =
            STATUS_SUCCESS;

        break;
    }


    default:
    {
        status =
            STATUS_INVALID_DEVICE_REQUEST;

        break;
    }
    }


    irp->IoStatus.Status =
        status;

    irp->IoStatus.Information =
        information;


    IoCompleteRequest(
        irp,
        IO_NO_INCREMENT
    );


    return status;
}