#pragma once

#include <ntifs.h>
#include "utils.hpp"

namespace helper
{
    namespace lifecycle
    {
        inline EX_RUNDOWN_REF& Requests()
        {
            static EX_RUNDOWN_REF requests = {};
            return requests;
        }
        inline VOID Initialize() { ExInitializeRundownProtection(&Requests()); }
        inline VOID Shutdown() { ExWaitForRundownProtectionRelease(&Requests()); }
    }


    namespace allocate
    {
        namespace usermode
        {
            // 프로세스 가상 메모리 할당
            inline NTSTATUS AllocVirtualMemory(
                _In_ HANDLE process_handle,
                _In_ SIZE_T size,
                _In_ ULONG protect,
                _Out_ PVOID* allocated_baseaddress
            )
            {
                if (
                    process_handle == nullptr ||
                    size == 0 ||
                    allocated_baseaddress == nullptr
                    )
                {
                    return STATUS_INVALID_PARAMETER;
                }

                *allocated_baseaddress = nullptr;

                PVOID base_address = nullptr;
                SIZE_T region_size = size;

                NTSTATUS status = ZwAllocateVirtualMemory(
                    process_handle,
                    &base_address,
                    0,
                    &region_size,
                    MEM_RESERVE | MEM_COMMIT,
                    protect
                );

                if (!NT_SUCCESS(status))
                    return status;

                *allocated_baseaddress = base_address;

                return STATUS_SUCCESS;
            }

            // 프로세스 가상 메모리 해제
            inline NTSTATUS FreeVirtualMemory(
                _In_ HANDLE process_handle,
                _In_ PVOID allocated_baseaddress
            )
            {
                if (
                    process_handle == nullptr ||
                    allocated_baseaddress == nullptr
                    )
                {
                    return STATUS_INVALID_PARAMETER;
                }

                PVOID base_address = allocated_baseaddress;
                SIZE_T region_size = 0;

                NTSTATUS status = ZwFreeVirtualMemory(
                    process_handle,
                    &base_address,
                    &region_size,
                    MEM_RELEASE
                );

                return status;
            }

            inline NTSTATUS ProtectVirtualMemory(
                _In_ HANDLE process_handle,
                _Inout_ PVOID* base_address,
                _Inout_ PSIZE_T region_size,
                _In_ ULONG new_protect,
                _Out_ PULONG old_protect
            )
            {
                if (
                    process_handle == nullptr ||
                    base_address == nullptr ||
                    region_size == nullptr ||
                    old_protect == nullptr
                    )
                {
                    return STATUS_INVALID_PARAMETER;
                }

                return ZwProtectVirtualMemory(
                    process_handle,
                    base_address,
                    region_size,
                    new_protect,
                    old_protect
                );
            }
        }

        namespace kernelmode
        {

            // 커널 가상메모리 할당
            inline PVOID AllocateKernelMemory(
                _In_ SIZE_T size
            )
            {
                if (size == 0)
                    return nullptr;

                KIRQL current_irql = KeGetCurrentIrql();

                if (current_irql > DISPATCH_LEVEL)
                    return nullptr;

                if (KeGetCurrentIrql() == PASSIVE_LEVEL)
                {
                    return ExAllocatePool2(POOL_FLAG_PAGED, size, 'KmHA');
                }
                return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'KmHA');
            }

            // 커널 가상메모리 해제
            inline VOID FreeKernelMemory(
                _In_opt_ PVOID address
            )
            {
                if (address == nullptr)
                    return;

                if (KeGetCurrentIrql() > DISPATCH_LEVEL)
                    return;

                ExFreePoolWithTag(
                    address,
                    'KmHA'
                );
            }
        }
    }

    namespace linkedlist
    {
        // Every producer must fit the bounded release routines.
        constexpr ULONG MAX_USER_RESULT_NODES = 65536;
        constexpr ULONGLONG LINKED_LIST_SIGNATURE =
            0x4C4C535448454C50ULL;

        typedef struct _LINKED_LIST_NODE
        {
            //
            // Node validation signature.
            //
            ULONGLONG Signature;

            //
            // All of these addresses except Signature/DataSize
            // are User Virtual Addresses belonging to
            // the target process.
            //
            PVOID Previous;
            PVOID Next;

            //
            // User VA containing copied data.
            //
            PVOID Data;

            ULONGLONG DataSize;

        } LINKED_LIST_NODE, * PLINKED_LIST_NODE;

        namespace usermode
        {
            inline PVOID InsertList(
                _In_ HANDLE process_handle,
                _In_opt_ PVOID latest_node_address,
                _In_ PUCHAR data, // 커널 또는 유저 주소 가능
                _In_ ULONGLONG data_size
            )
            {
                //
                // This helper works only at PASSIVE_LEVEL.
                //
                if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                    return nullptr;

                if (
                    process_handle == nullptr ||
                    data == nullptr ||
                    data_size == 0
                    )
                {
                    return nullptr;
                }

                //
                // Prevent ULONGLONG -> SIZE_T truncation.
                //
                if (data_size > static_cast<ULONGLONG>(MAXSIZE_T))
                    return nullptr;

                SIZE_T copy_size =
                    static_cast<SIZE_T>(data_size);


                //
                // Obtain referenced EPROCESS from supplied handle.
                //
                PEPROCESS process = nullptr;

                NTSTATUS status = ObReferenceObjectByHandle(
                    process_handle,
                    0,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(&process),
                    nullptr
                );

                if (!NT_SUCCESS(status))
                    return nullptr;


                //
                // ---------------------------------------------------------
                // Allocate Data buffer in target process User VA.
                // ---------------------------------------------------------
                //

                PVOID user_data_address = nullptr;

                status = helper::allocate::usermode::AllocVirtualMemory(
                    process_handle,
                    copy_size,
                    PAGE_READWRITE,
                    &user_data_address
                );

                if (!NT_SUCCESS(status))
                {
                    ObDereferenceObject(process);
                    return nullptr;
                }


                //
                // ---------------------------------------------------------
                // Allocate linked-list node in target process User VA.
                // ---------------------------------------------------------
                //

                PVOID user_node_address = nullptr;

                status = helper::allocate::usermode::AllocVirtualMemory(
                    process_handle,
                    sizeof(LINKED_LIST_NODE),
                    PAGE_READWRITE,
                    &user_node_address
                );

                if (!NT_SUCCESS(status))
                {
                    helper::allocate::usermode::FreeVirtualMemory(
                        process_handle,
                        user_data_address
                    );

                    ObDereferenceObject(process);

                    return nullptr;
                }


                //
                // Build node safely in kernel stack memory first.
                //
                LINKED_LIST_NODE new_node = {};

                new_node.Signature =
                    LINKED_LIST_SIGNATURE;

                new_node.Previous =
                    latest_node_address;

                new_node.Next =
                    nullptr;

                new_node.Data =
                    user_data_address;

                new_node.DataSize =
                    data_size;


                //
                // ---------------------------------------------------------
                // Attach to target process.
                //
                // From this point:
                //
                //   target process User VA -> accessible
                //   kernel VA              -> accessible
                //
                // Keep attached section short.
                // ---------------------------------------------------------
                //

                KAPC_STATE apc_state = {};

                BOOLEAN success = FALSE;

                KeStackAttachProcess(
                    process,
                    &apc_state
                );

                __try
                {
                    //
                    // -----------------------------------------------------
                    // Validate source data when source belongs to
                    // UserMode address range.
                    //
                    // IMPORTANT:
                    //
                    // User VA must belong to THIS target process,
                    // because we're currently attached to this process.
                    // -----------------------------------------------------
                    //

                    if (
                        reinterpret_cast<ULONG_PTR>(data) <=
                        reinterpret_cast<ULONG_PTR>(MmHighestUserAddress)
                        )
                    {
                        ProbeForRead(
                            data,
                            copy_size,
                            sizeof(UCHAR)
                        );
                    }


                    //
                    // Validate newly allocated UserMode destination.
                    //
                    ProbeForWrite(
                        user_data_address,
                        copy_size,
                        sizeof(UCHAR)
                    );


                    //
                    // -----------------------------------------------------
                    // Copy:
                    //
                    // Kernel VA -> Target User VA
                    //
                    // or
                    //
                    // Target User VA -> Target User VA
                    // -----------------------------------------------------
                    //

                    RtlCopyMemory(
                        user_data_address,
                        data,
                        copy_size
                    );


                    //
                    // -----------------------------------------------------
                    // Write newly created node.
                    // -----------------------------------------------------
                    //

                    ProbeForWrite(
                        user_node_address,
                        sizeof(LINKED_LIST_NODE),
                        __alignof(LINKED_LIST_NODE)
                    );

                    RtlCopyMemory(
                        user_node_address,
                        &new_node,
                        sizeof(LINKED_LIST_NODE)
                    );


                    //
                    // -----------------------------------------------------
                    // If latest_node_address exists:
                    //
                    // ExistingLastNode.Next = NewNode
                    // -----------------------------------------------------
                    //

                    if (latest_node_address != nullptr)
                    {
                        LINKED_LIST_NODE previous_node = {};


                        //
                        // Read existing latest node.
                        //
                        ProbeForRead(
                            latest_node_address,
                            sizeof(LINKED_LIST_NODE),
                            __alignof(LINKED_LIST_NODE)
                        );

                        RtlCopyMemory(
                            &previous_node,
                            latest_node_address,
                            sizeof(LINKED_LIST_NODE)
                        );


                        //
                        // Validate that the supplied address actually
                        // points to one of our linked-list nodes.
                        //
                        if (
                            previous_node.Signature !=
                            LINKED_LIST_SIGNATURE
                            )
                        {
                            __leave;
                        }


                        //
                        // latest_node_address must actually represent
                        // the last node.
                        //
                        if (previous_node.Next != nullptr)
                            __leave;


                        //
                        // Connect previous node -> new node.
                        //
                        previous_node.Next =
                            user_node_address;


                        ProbeForWrite(
                            latest_node_address,
                            sizeof(LINKED_LIST_NODE),
                            __alignof(LINKED_LIST_NODE)
                        );

                        RtlCopyMemory(
                            latest_node_address,
                            &previous_node,
                            sizeof(LINKED_LIST_NODE)
                        );
                    }


                    success = TRUE;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    success = FALSE;
                }


                KeUnstackDetachProcess(
                    &apc_state
                );


                //
                // Release EPROCESS reference.
                //
                ObDereferenceObject(
                    process
                );


                //
                // ---------------------------------------------------------
                // Rollback allocations if insertion failed.
                //
                // Existing linked-list remains untouched unless the
                // final connection step completed successfully.
                // ---------------------------------------------------------
                //

                if (!success)
                {
                    helper::allocate::usermode::FreeVirtualMemory(
                        process_handle,
                        user_node_address
                    );

                    helper::allocate::usermode::FreeVirtualMemory(
                        process_handle,
                        user_data_address
                    );

                    return nullptr;
                }


                //
                // Returned address is a User Virtual Address.
                //
                // Caller can use this directly as latest_node_address
                // for the next InsertList() call.
                //
                return user_node_address;
            }



            inline NTSTATUS FreeLinkedList(
                _In_ HANDLE process_handle,
                _In_opt_ PVOID first_node_address
            )
            {
                //
                // PASSIVE_LEVEL only.
                //
                if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                    return STATUS_INVALID_DEVICE_STATE;

                if (process_handle == nullptr)
                    return STATUS_INVALID_PARAMETER;

                if (first_node_address == nullptr)
                    return STATUS_SUCCESS;


                //
                // Obtain referenced EPROCESS.
                //
                PEPROCESS process = nullptr;

                NTSTATUS status = ObReferenceObjectByHandle(
                    process_handle,
                    0,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(&process),
                    nullptr
                );

                if (!NT_SUCCESS(status))
                    return status;


                PVOID current_node_address =
                    first_node_address;

                PVOID expected_previous_address =
                    nullptr;

                ULONG nodes_processed = 0;
                constexpr ULONG MAX_LINKED_LIST_NODES = MAX_USER_RESULT_NODES;

                while (current_node_address != nullptr)
                {
                    if (++nodes_processed > MAX_LINKED_LIST_NODES)
                    {
                        status = STATUS_DATA_OVERRUN;
                        break;
                    }

                    LINKED_LIST_NODE current_node = {};

                    BOOLEAN read_success = FALSE;

                    KAPC_STATE apc_state = {};


                    //
                    // -----------------------------------------------------
                    // Attach only long enough to copy node metadata
                    // into kernel stack memory.
                    // -----------------------------------------------------
                    //

                    KeStackAttachProcess(
                        process,
                        &apc_state
                    );

                    __try
                    {
                        ProbeForRead(
                            current_node_address,
                            sizeof(LINKED_LIST_NODE),
                            __alignof(LINKED_LIST_NODE)
                        );

                        RtlCopyMemory(
                            &current_node,
                            current_node_address,
                            sizeof(LINKED_LIST_NODE)
                        );

                        read_success = TRUE;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        status = GetExceptionCode();
                        read_success = FALSE;
                    }


                    KeUnstackDetachProcess(
                        &apc_state
                    );


                    if (!read_success)
                        break;


                    //
                    // -----------------------------------------------------
                    // Validate node signature.
                    // -----------------------------------------------------
                    //

                    if (
                        current_node.Signature !=
                        LINKED_LIST_SIGNATURE
                        )
                    {
                        status = STATUS_DATA_ERROR;
                        break;
                    }


                    //
                    // -----------------------------------------------------
                    // Validate Previous chain.
                    //
                    // Helps detect malformed or unexpected list.
                    // -----------------------------------------------------
                    //

                    if (
                        current_node.Previous !=
                        expected_previous_address
                        )
                    {
                        status = STATUS_DATA_ERROR;
                        break;
                    }


                    //
                    // Save next address BEFORE freeing current node.
                    //
                    PVOID next_node_address =
                        current_node.Next;


                    //
                    // -----------------------------------------------------
                    // Free node Data first.
                    // -----------------------------------------------------
                    //

                    if (current_node.Data != nullptr)
                    {
                        NTSTATUS free_status =
                            helper::allocate::usermode::FreeVirtualMemory(
                                process_handle,
                                current_node.Data
                            );

                        if (!NT_SUCCESS(free_status))
                        {
                            status = free_status;
                            break;
                        }
                    }


                    //
                    // -----------------------------------------------------
                    // Free node itself.
                    // -----------------------------------------------------
                    //

                    NTSTATUS free_status =
                        helper::allocate::usermode::FreeVirtualMemory(
                            process_handle,
                            current_node_address
                        );

                    if (!NT_SUCCESS(free_status))
                    {
                        status = free_status;
                        break;
                    }


                    expected_previous_address =
                        current_node_address;

                    current_node_address =
                        next_node_address;

                    status = STATUS_SUCCESS;
                }


                ObDereferenceObject(
                    process
                );

                return status;
            }
        }

        namespace kernelmode
        {
            constexpr ULONG LINKED_LIST_POOL_TAG =
                'LmHL';


            inline PLINKED_LIST_NODE InsertList(
                _In_opt_ PLINKED_LIST_NODE latest_node,
                _In_ PUCHAR data,
                _In_ ULONGLONG data_size
            )
            {
                //
                // ExAllocatePool2 supports up to DISPATCH_LEVEL.
                //
                if (KeGetCurrentIrql() > DISPATCH_LEVEL)
                    return nullptr;

                if (
                    data == nullptr ||
                    data_size == 0
                    )
                {
                    return nullptr;
                }

                if (data_size > static_cast<ULONGLONG>(MAXSIZE_T))
                    return nullptr;


                SIZE_T copy_size =
                    static_cast<SIZE_T>(data_size);


                //
                // IMPORTANT:
                //
                // Always allocate NON_PAGED memory because this linked-list
                // may later be accessed at DISPATCH_LEVEL.
                //
                PVOID data_buffer = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    copy_size,
                    LINKED_LIST_POOL_TAG
                );

                if (data_buffer == nullptr)
                    return nullptr;


                PLINKED_LIST_NODE new_node =
                    static_cast<PLINKED_LIST_NODE>(
                        ExAllocatePool2(
                            POOL_FLAG_NON_PAGED,
                            sizeof(LINKED_LIST_NODE),
                            LINKED_LIST_POOL_TAG
                        )
                        );

                if (new_node == nullptr)
                {
                    ExFreePoolWithTag(
                        data_buffer,
                        LINKED_LIST_POOL_TAG
                    );

                    return nullptr;
                }


                //
                // ExAllocatePool2 memory is zero-initialized by default.
                //

                new_node->Signature =
                    LINKED_LIST_SIGNATURE;

                new_node->Previous =
                    latest_node;

                new_node->Next =
                    nullptr;

                new_node->Data =
                    data_buffer;

                new_node->DataSize =
                    data_size;


                //
                // Copy supplied kernel buffer.
                //
                // At DISPATCH_LEVEL the caller must guarantee that
                // "data" itself is resident/nonpaged and accessible
                // at the current IRQL.
                //
                RtlCopyMemory(
                    data_buffer,
                    data,
                    copy_size
                );


                //
                // Connect previous latest node.
                //
                if (latest_node != nullptr)
                {
                    //
                    // Verify supplied node belongs to this linked-list.
                    //
                    if (
                        latest_node->Signature !=
                        LINKED_LIST_SIGNATURE
                        )
                    {
                        ExFreePoolWithTag(
                            new_node,
                            LINKED_LIST_POOL_TAG
                        );

                        ExFreePoolWithTag(
                            data_buffer,
                            LINKED_LIST_POOL_TAG
                        );

                        return nullptr;
                    }


                    //
                    // Must actually be the latest node.
                    //
                    if (latest_node->Next != nullptr)
                    {
                        ExFreePoolWithTag(
                            new_node,
                            LINKED_LIST_POOL_TAG
                        );

                        ExFreePoolWithTag(
                            data_buffer,
                            LINKED_LIST_POOL_TAG
                        );

                        return nullptr;
                    }


                    latest_node->Next =
                        new_node;
                }


                //
                // Return newly-created latest node.
                //
                return new_node;
            }



            inline NTSTATUS FreeLinkedList(
                _In_opt_ PLINKED_LIST_NODE first_node
            )
            {
                if (KeGetCurrentIrql() > DISPATCH_LEVEL)
                    return STATUS_INVALID_DEVICE_STATE;

                if (first_node == nullptr)
                    return STATUS_SUCCESS;


                PLINKED_LIST_NODE current_node =
                    first_node;

                PLINKED_LIST_NODE expected_previous =
                    nullptr;


                while (current_node != nullptr)
                {
                    //
                    // Validate node.
                    //
                    if (
                        current_node->Signature !=
                        LINKED_LIST_SIGNATURE
                        )
                    {
                        return STATUS_DATA_ERROR;
                    }


                    //
                    // Validate backward linkage.
                    //
                    if (
                        current_node->Previous !=
                        expected_previous
                        )
                    {
                        return STATUS_DATA_ERROR;
                    }


                    //
                    // Save Next BEFORE current node gets released.
                    //
                    PLINKED_LIST_NODE next_node =
                        static_cast<PLINKED_LIST_NODE>(
                            current_node->Next
                            );


                    //
                    // Free copied Data.
                    //
                    if (current_node->Data != nullptr)
                    {
                        ExFreePoolWithTag(
                            current_node->Data,
                            LINKED_LIST_POOL_TAG
                        );

                        current_node->Data =
                            nullptr;
                    }


                    //
                    // Save current address only for validating
                    // next_node->Previous.
                    //
                    expected_previous =
                        current_node;


                    //
                    // Free current node itself.
                    //
                    ExFreePoolWithTag(
                        current_node,
                        LINKED_LIST_POOL_TAG
                    );


                    current_node =
                        next_node;
                }


                return STATUS_SUCCESS;
            }
        }
    }

    namespace driver
    {
        typedef struct _CREATE_DRIVER_CONTEXT
        {
            PDRIVER_OBJECT DriverObject;
            NTSTATUS InitializationStatus;

        } CREATE_DRIVER_CONTEXT,
            * PCREATE_DRIVER_CONTEXT;


        extern CREATE_DRIVER_CONTEXT*
            g_CreateDriverContext = nullptr;


        inline DRIVER_INITIALIZE CreateDriverInitializeRoutine;

        inline NTSTATUS CreateDriverInitializeRoutine(
            _In_ PDRIVER_OBJECT driver_object,
            _In_ PUNICODE_STRING registry_path
        )
        {
            UNREFERENCED_PARAMETER(
                registry_path
            );


            if (g_CreateDriverContext == nullptr)
                return STATUS_INVALID_DEVICE_STATE;


            g_CreateDriverContext->DriverObject =
                driver_object;


            g_CreateDriverContext->InitializationStatus =
                STATUS_SUCCESS;


            return STATUS_SUCCESS;
        }


        inline NTSTATUS CreateDriver(
            _In_ PCWSTR driver_object_name,
            _Out_ PDRIVER_OBJECT* created_driver_object
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;


            if (
                driver_object_name == nullptr ||
                created_driver_object == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            *created_driver_object =
                nullptr;


            //
            // --------------------------------------------------------
            // Convert WCHAR* -> UNICODE_STRING
            // --------------------------------------------------------
            //

            UNICODE_STRING driver_name = {};


            RtlInitUnicodeString(
                &driver_name,
                driver_object_name
            );


            //
            // --------------------------------------------------------
            // Temporary callback context
            // --------------------------------------------------------
            //

            CREATE_DRIVER_CONTEXT context = {};


            //
            // Current simple implementation allows only
            // one CreateDriver() operation at a time.
            //
            if (InterlockedCompareExchangePointer(
                reinterpret_cast<PVOID volatile*>(&g_CreateDriverContext), &context, nullptr) != nullptr)
                return STATUS_DEVICE_BUSY;


            //
            // --------------------------------------------------------
            // Create DRIVER_OBJECT.
            //
            // IoCreateDriver will invoke:
            //
            //      CreateDriverInitializeRoutine(
            //          PDRIVER_OBJECT,
            //          PUNICODE_STRING
            //      )
            //
            // --------------------------------------------------------
            //

            NTSTATUS status =
                IoCreateDriver(
                    &driver_name,
                    CreateDriverInitializeRoutine
                );


            //
            // Callback has completed before IoCreateDriver returns.
            //
            InterlockedExchangePointer(
                reinterpret_cast<PVOID volatile*>(&g_CreateDriverContext), nullptr);


            if (!NT_SUCCESS(status))
                return status;


            if (
                context.DriverObject ==
                nullptr
                )
            {
                return STATUS_UNSUCCESSFUL;
            }


            if (
                !NT_SUCCESS(
                    context.InitializationStatus
                )
                )
            {
                return context.InitializationStatus;
            }


            *created_driver_object =
                context.DriverObject;


            return STATUS_SUCCESS;
        }
    }

    namespace instance
    {
        template<typename T>
        T* GenerateClassInstance()
        {
            PVOID mem = ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(T),
                'ClsA'
            );

            if (mem == nullptr)
                return nullptr;

            return new (mem) T();
        }

        template<typename T>
        VOID TerminateClassInstance(T* object)
        {
            if (object == nullptr)
                return;

            object->~T();

            ExFreePoolWithTag(
                object,
                'ClsA'
            );
        }
    }

    namespace process
    {

        namespace hwbp_internal
        {

            enum class HARDWARE_BREAKPOINT_TYPE : ULONG { Execute = 0, Write = 1, ReadWrite = 3 };
            enum class HARDWARE_BREAKPOINT_LENGTH : ULONG { Byte1 = 1, Byte2 = 2, Byte4 = 4, Byte8 = 8 };

            typedef struct _HARDWARE_BREAKPOINT_INFORMATION
            {
                HANDLE ProcessId;
                HANDLE ThreadId;
                ULONG Slot;
                PVOID Address;
                HARDWARE_BREAKPOINT_TYPE Type;
                HARDWARE_BREAKPOINT_LENGTH Length;
                BOOLEAN Enabled;
                ULONGLONG Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            } HARDWARE_BREAKPOINT_INFORMATION, * PHARDWARE_BREAKPOINT_INFORMATION;

            typedef struct _HARDWARE_BREAKPOINT_REQUEST
            {
                HANDLE ProcessId;
                PVOID Address;
                HARDWARE_BREAKPOINT_TYPE Type;
                HARDWARE_BREAKPOINT_LENGTH Length;
                ULONG Slot;
            } HARDWARE_BREAKPOINT_REQUEST, * PHARDWARE_BREAKPOINT_REQUEST;

            constexpr ULONG PoolTag = 'pBwH';
            constexpr ULONG MaximumEntries = 16384;
            constexpr ULONG MaximumSystemBuffer = 64 * 1024 * 1024;

            // No mutex/critical region: context APIs need APC delivery to remain possible.
            // This serializes this implementation only, not external debuggers/drivers.
            inline volatile LONG* OperationGate()
            {
                static volatile LONG gate = 0;
                return &gate;
            }

            inline PVOID Allocate(SIZE_T size)
            {
                return size ? ExAllocatePool2(POOL_FLAG_NON_PAGED, size, PoolTag) : nullptr;
            }
            inline VOID Free(PVOID memory)
            {
                if (memory) ExFreePoolWithTag(memory, PoolTag);
            }
            inline VOID RecordFailure(NTSTATUS& status, NTSTATUS next)
            {
                if (NT_SUCCESS(status) && !NT_SUCCESS(next)) status = next;
            }
            inline BOOLEAN UserRange(PVOID address, SIZE_T size)
            {
                const ULONG_PTR start = reinterpret_cast<ULONG_PTR>(address);
                const ULONG_PTR top = reinterpret_cast<ULONG_PTR>(MmHighestUserAddress);
                return start != 0 && size != 0 && start <= top && size - 1 <= top - start;
            }

            inline ULONGLONG GetDrValue(const CONTEXT& c, ULONG slot)
            {
                switch (slot) {
                case 0: return c.Dr0; case 1: return c.Dr1;
                case 2: return c.Dr2; case 3: return c.Dr3; default: return 0;
                }
            }
            inline BOOLEAN SetDrValue(CONTEXT& c, ULONG slot, ULONGLONG value)
            {
                switch (slot) {
                case 0: c.Dr0 = value; break; case 1: c.Dr1 = value; break;
                case 2: c.Dr2 = value; break; case 3: c.Dr3 = value; break;
                default: return FALSE;
                }
                return TRUE;
            }
            inline ULONGLONG GetDr7EnableMask(ULONG slot)
            {
                return slot < 4 ? 3ULL << (slot * 2) : 0;
            }
            inline ULONGLONG GetDr7ConditionMask(ULONG slot)
            {
                return slot < 4 ? 15ULL << (16 + slot * 4) : 0;
            }
            inline ULONGLONG GetDr7SlotMask(ULONG slot)
            {
                return GetDr7EnableMask(slot) | GetDr7ConditionMask(slot);
            }
            inline BOOLEAN IsSlotEnabled(ULONGLONG dr7, ULONG slot)
            {
                return (dr7 & GetDr7EnableMask(slot)) != 0;
            }
            inline BOOLEAN IsSlotFree(const CONTEXT& c, ULONG slot)
            {
                return slot < 4 && !IsSlotEnabled(c.Dr7, slot) && GetDrValue(c, slot) == 0;
            }
            inline LONG FindFreeSlot(const CONTEXT& c)
            {
                for (ULONG i = 0; i < 4; ++i) if (IsSlotFree(c, i)) return static_cast<LONG>(i);
                return -1;
            }
            inline ULONG EncodeType(HARDWARE_BREAKPOINT_TYPE type)
            {
                return static_cast<ULONG>(type);
            }
            inline ULONG EncodeLength(HARDWARE_BREAKPOINT_LENGTH length)
            {
                switch (length) {
                case HARDWARE_BREAKPOINT_LENGTH::Byte2: return 1;
                case HARDWARE_BREAKPOINT_LENGTH::Byte4: return 3;
                case HARDWARE_BREAKPOINT_LENGTH::Byte8: return 2; default: return 0;
                }
            }
            inline HARDWARE_BREAKPOINT_TYPE DecodeType(ULONGLONG dr7, ULONG slot)
            {
                return slot < 4 ? static_cast<HARDWARE_BREAKPOINT_TYPE>((dr7 >> (16 + slot * 4)) & 3)
                    : HARDWARE_BREAKPOINT_TYPE::Execute;
            }
            inline HARDWARE_BREAKPOINT_LENGTH DecodeLength(ULONGLONG dr7, ULONG slot)
            {
                if (slot >= 4) return HARDWARE_BREAKPOINT_LENGTH::Byte1;
                switch ((dr7 >> (18 + slot * 4)) & 3) {
                case 1: return HARDWARE_BREAKPOINT_LENGTH::Byte2;
                case 2: return HARDWARE_BREAKPOINT_LENGTH::Byte8;
                case 3: return HARDWARE_BREAKPOINT_LENGTH::Byte4;
                default: return HARDWARE_BREAKPOINT_LENGTH::Byte1;
                }
            }
            inline VOID ClearDr7Slot(ULONGLONG& dr7, ULONG slot)
            {
                dr7 &= ~GetDr7SlotMask(slot);
            }
            inline ULONGLONG ExtractDr7SlotBits(ULONGLONG dr7, ULONG slot)
            {
                return dr7 & GetDr7SlotMask(slot);
            }
            inline VOID RestoreDr7Slot(ULONGLONG& dr7, ULONG slot, ULONGLONG bits)
            {
                const ULONGLONG mask = GetDr7SlotMask(slot); dr7 = (dr7 & ~mask) | (bits & mask);
            }
            inline VOID ConfigureDr7Slot(ULONGLONG& dr7, ULONG slot,
                HARDWARE_BREAKPOINT_TYPE type, HARDWARE_BREAKPOINT_LENGTH length)
            {
                if (slot >= 4) return;
                ClearDr7Slot(dr7, slot);
                dr7 |= (1ULL << (slot * 2)) |
                    (static_cast<ULONGLONG>(EncodeType(type)) << (16 + slot * 4)) |
                    (static_cast<ULONGLONG>(EncodeLength(length)) << (18 + slot * 4));
            }
            inline NTSTATUS ValidateBreakpoint(PVOID address, HARDWARE_BREAKPOINT_TYPE type,
                HARDWARE_BREAKPOINT_LENGTH length)
            {
                if (type != HARDWARE_BREAKPOINT_TYPE::Execute && type != HARDWARE_BREAKPOINT_TYPE::Write &&
                    type != HARDWARE_BREAKPOINT_TYPE::ReadWrite) return STATUS_INVALID_PARAMETER;
                if (length != HARDWARE_BREAKPOINT_LENGTH::Byte1 && length != HARDWARE_BREAKPOINT_LENGTH::Byte2 &&
                    length != HARDWARE_BREAKPOINT_LENGTH::Byte4 && length != HARDWARE_BREAKPOINT_LENGTH::Byte8)
                    return STATUS_INVALID_PARAMETER;
                if (!UserRange(address, static_cast<SIZE_T>(length))) return STATUS_INVALID_PARAMETER;
                if (type == HARDWARE_BREAKPOINT_TYPE::Execute && length != HARDWARE_BREAKPOINT_LENGTH::Byte1)
                    return STATUS_INVALID_PARAMETER;
                if (reinterpret_cast<ULONG_PTR>(address) % static_cast<ULONG>(length))
                    return STATUS_DATATYPE_MISALIGNMENT;
                return STATUS_SUCCESS;
            }
            inline BOOLEAN VerifyInstalledBreakpoint(const CONTEXT& c, ULONG slot, PVOID address,
                HARDWARE_BREAKPOINT_TYPE type, HARDWARE_BREAKPOINT_LENGTH length)
            {
                return slot < 4 && IsSlotEnabled(c.Dr7, slot) &&
                    GetDrValue(c, slot) == reinterpret_cast<ULONGLONG>(address) &&
                    DecodeType(c.Dr7, slot) == type && DecodeLength(c.Dr7, slot) == length;
            }
            inline NTSTATUS BuildBreakpointContext(const CONTEXT& original, PVOID address,
                HARDWARE_BREAKPOINT_TYPE type, HARDWARE_BREAKPOINT_LENGTH length, PCONTEXT output,
                PULONG slot, PULONGLONG originalDr, PULONGLONG originalBits)
            {
                if (!output || !slot || !originalDr || !originalBits) return STATUS_INVALID_PARAMETER;
                NTSTATUS status = ValidateBreakpoint(address, type, length);
                if (!NT_SUCCESS(status)) return status;
                LONG freeSlot = FindFreeSlot(original);
                if (freeSlot < 0) return STATUS_INSUFFICIENT_RESOURCES;
                *slot = static_cast<ULONG>(freeSlot);
                *originalDr = GetDrValue(original, *slot);
                *originalBits = ExtractDr7SlotBits(original.Dr7, *slot);
                *output = original;
                output->ContextFlags = CONTEXT_DEBUG_REGISTERS;
                SetDrValue(*output, *slot, reinterpret_cast<ULONGLONG>(address));
                ConfigureDr7Slot(output->Dr7, *slot, type, length);
                return STATUS_SUCCESS;
            }
            inline NTSTATUS BuildRestoreContext(const CONTEXT& current, ULONG slot,
                ULONGLONG originalDr, ULONGLONG originalBits, PCONTEXT output)
            {
                if (!output || slot >= 4) return STATUS_INVALID_PARAMETER;
                *output = current;
                output->ContextFlags = CONTEXT_DEBUG_REGISTERS;
                SetDrValue(*output, slot, originalDr);
                RestoreDr7Slot(output->Dr7, slot, originalBits);
                return STATUS_SUCCESS;
            }

            typedef struct _THREAD_SNAPSHOT_ITEM
            {
                HANDLE ThreadId;
                PETHREAD ThreadObject; // One owned reference; no per-thread handle/suspend count.
                CONTEXT OriginalContext;
                CONTEXT NewContext;
                BOOLEAN ContextCaptured;
                BOOLEAN WriteAttempted; // Includes a failing SET: conservatively roll it back too.
                BOOLEAN Selected;
            } THREAD_SNAPSHOT_ITEM, * PTHREAD_SNAPSHOT_ITEM;

            inline VOID CleanupThreadSnapshot(PTHREAD_SNAPSHOT_ITEM items, ULONG count)
            {
                if (!items) return;
                for (ULONG i = 0; i < count; ++i)
                    if (items[i].ThreadObject) ObDereferenceObject(items[i].ThreadObject);
                Free(items);
            }

            // Snapshot membership is fixed here. Threads created later are not covered.
            inline NTSTATUS QueryProcessThreadList(PEPROCESS target, PTHREAD_SNAPSHOT_ITEM* output, PULONG count)
            {
                *output = nullptr;
                *count = 0;
                PVOID buffer = nullptr;
                ULONG size = 0x10000;
                ULONG returned = 0;
                NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
                for (ULONG retry = 0; retry < 12; ++retry)
                {
                    buffer = Allocate(size);
                    if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;
                    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, size, &returned);
                    if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) break;
                    Free(buffer);
                    buffer = nullptr;
                    if (size >= MaximumSystemBuffer || returned > MaximumSystemBuffer)
                        return STATUS_INSUFFICIENT_RESOURCES;
                    size = returned > size ? returned : size * 2;
                    if (size > MaximumSystemBuffer) size = MaximumSystemBuffer;
                }
                if (!NT_SUCCESS(status)) { Free(buffer); return status; }
                if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;
                const SIZE_T bytes = returned && returned <= size ? returned : size;
                SIZE_T offset = 0;
                status = STATUS_NOT_FOUND;
                while (offset < bytes)
                {
                    const SIZE_T header = FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, Threads);
                    if (bytes - offset < header) { status = STATUS_DATA_ERROR; break; }
                    auto info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(static_cast<PUCHAR>(buffer) + offset);
                    const SIZE_T span = info->NextEntryOffset ? info->NextEntryOffset : bytes - offset;
                    if (span < header || span > bytes - offset ||
                        info->NumberOfThreads > (span - header) / sizeof(info->Threads[0]))
                    {
                        status = STATUS_DATA_ERROR; break;
                    }
                    if (info->UniqueProcessId == PsGetProcessId(target))
                    {
                        const ULONG capacity = info->NumberOfThreads;
                        if (!capacity) break;
                        if (capacity > MaximumEntries) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
                        auto items = static_cast<PTHREAD_SNAPSHOT_ITEM>(Allocate(sizeof(THREAD_SNAPSHOT_ITEM) * capacity));
                        if (!items) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
                        ULONG used = 0;
                        status = STATUS_SUCCESS;
                        for (ULONG i = 0; i < capacity; ++i)
                        {
                            PETHREAD thread = nullptr;
                            NTSTATUS lookup = PsLookupThreadByThreadId(info->Threads[i].ClientId.UniqueThread, &thread);
                            if (lookup == STATUS_INVALID_CID || lookup == STATUS_THREAD_IS_TERMINATING) continue;
                            if (!NT_SUCCESS(lookup)) { status = lookup; break; }
                            if (IoThreadToProcess(thread) != target || PsIsThreadTerminating(thread))
                            {
                                ObDereferenceObject(thread); continue;
                            }
                            if (thread == PsGetCurrentThread() || PsIsSystemThread(thread))
                            {
                                ObDereferenceObject(thread); status = STATUS_INVALID_DEVICE_STATE; break;
                            }
                            items[used].ThreadObject = thread;
                            items[used].ThreadId = PsGetThreadId(thread);
                            ++used;
                        }
                        if (NT_SUCCESS(status) && used) { *output = items; *count = used; }
                        else { CleanupThreadSnapshot(items, used); if (NT_SUCCESS(status)) status = STATUS_NOT_FOUND; }
                        break;
                    }
                    if (!info->NextEntryOffset) break;
                    offset += info->NextEntryOffset;
                }
                Free(buffer);
                return status;
            }

            struct LOCKED_USER_BUFFER
            {
                PVOID Address;
                PMDL Mdl;
                PVOID Mapping;
                BOOLEAN Locked;
            };
            inline NTSTATUS AllocateUser(HANDLE process, SIZE_T size, PVOID* address)
            {
                *address = nullptr;
                return ZwAllocateVirtualMemory(process, address, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            }
            inline NTSTATUS ReleaseUser(HANDLE process, PVOID address)
            {
                if (!address) return STATUS_SUCCESS;
                SIZE_T zero = 0;
                PVOID allocation = address;
                NTSTATUS status = ZwFreeVirtualMemory(process, &address, &zero, MEM_RELEASE);
                if (!NT_SUCCESS(status))
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[HWBP] VM release handle=%p address=%p status=0x%08lX\n",
                        process, allocation, static_cast<ULONG>(status));
                return status;
            }
            // Caller is attached to the address owner's process. SEH covers user probes.
            inline NTSTATUS LockUser(LOCKED_USER_BUFFER& b, ULONG bytes)
            {
                b.Mdl = IoAllocateMdl(b.Address, bytes, FALSE, FALSE, nullptr);
                if (!b.Mdl) return STATUS_INSUFFICIENT_RESOURCES;
                NTSTATUS status = STATUS_SUCCESS;
                __try
                {
                    MmProbeAndLockPages(b.Mdl, UserMode, IoModifyAccess);
                    b.Locked = TRUE;
                    b.Mapping = MmGetSystemAddressForMdlSafe(b.Mdl, NormalPagePriority | MdlMappingNoExecute);
                    if (!b.Mapping) status = STATUS_INSUFFICIENT_RESOURCES;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
                return status;
            }
            inline VOID UnlockUser(LOCKED_USER_BUFFER& b)
            {
                if (b.Locked) MmUnlockPages(b.Mdl); // Also releases the system mapping.
                if (b.Mdl) IoFreeMdl(b.Mdl);
                b.Mdl = nullptr; b.Mapping = nullptr; b.Locked = FALSE;
            }

            struct TRANSACTION
            {
                PEPROCESS Target;
                PEPROCESS Request;
                HANDLE TargetHandle;
                HANDLE RequestHandle;
                PTHREAD_SNAPSHOT_ITEM Items;
                ULONG Count;
                LOCKED_USER_BUFFER UserContext;
                KAPC_STATE ApcState;
                BOOLEAN Attached;
                BOOLEAN Suspended;
                BOOLEAN Committed;
                NTSTATUS RollbackStatus;
                NTSTATUS ResumeStatus;
            };

            inline NTSTATUS OpenReferencedProcess(HANDLE input, PEPROCESS* process, PHANDLE ownedHandle)
            {
                // input comes from the existing IOCTL's OBJ_KERNEL_HANDLE open path.
                NTSTATUS status = ObReferenceObjectByHandle(input, 0, *PsProcessType, KernelMode,
                    reinterpret_cast<PVOID*>(process), nullptr);
                if (!NT_SUCCESS(status)) return status;
                return ObOpenObjectByPointer(*process, OBJ_KERNEL_HANDLE, nullptr,
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                    *PsProcessType, KernelMode, ownedHandle);
            }
            inline NTSTATUS PrepareTransaction(TRANSACTION& t, HANDLE request, HANDLE target)
            {
                if (!request || !target) return STATUS_INVALID_PARAMETER;
                NTSTATUS status = OpenReferencedProcess(target, &t.Target, &t.TargetHandle);
                if (!NT_SUCCESS(status)) return status;
                status = OpenReferencedProcess(request, &t.Request, &t.RequestHandle);
                if (!NT_SUCCESS(status)) return status;
                if (t.Target == t.Request || t.Target == IoThreadToProcess(PsGetCurrentThread()) ||
                    t.Target == PsInitialSystemProcess) return STATUS_INVALID_DEVICE_STATE;
                if (PsGetProcessWow64Process(t.Target) || PsGetProcessWow64Process(t.Request))
                    return STATUS_NOT_SUPPORTED;
                status = QueryProcessThreadList(t.Target, &t.Items, &t.Count);
                if (!NT_SUCCESS(status)) return status;
                return AllocateUser(t.TargetHandle, sizeof(CONTEXT), &t.UserContext.Address);
            }
            inline NTSTATUS BeginTransaction(TRANSACTION& t)
            {
                KeStackAttachProcess(t.Target, &t.ApcState);
                t.Attached = TRUE;
                NTSTATUS status = LockUser(t.UserContext, sizeof(CONTEXT));
                if (!NT_SUCCESS(status)) return status;
                __try { RtlZeroMemory(t.UserContext.Address, sizeof(CONTEXT)); }
                __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
                status = PsSuspendProcess(t.Target); // The ONLY suspend call per transaction.
                if (NT_SUCCESS(status)) t.Suspended = TRUE;
                return status;
            }
            inline NTSTATUS CaptureDebugContextUserMode(TRANSACTION& t, THREAD_SNAPSHOT_ITEM& item)
            {
                if (!t.Attached || !t.Suspended || !item.ThreadObject) return STATUS_INVALID_DEVICE_STATE;
                NTSTATUS status = STATUS_SUCCESS;
                __try
                {
                    auto user = static_cast<PCONTEXT>(t.UserContext.Address);
                    RtlZeroMemory(user, sizeof(CONTEXT));
                    user->ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    status = PsGetContextThread(item.ThreadObject, user, UserMode);
                    if (NT_SUCCESS(status))
                    {
                        RtlCopyMemory(&item.OriginalContext, user, sizeof(CONTEXT));
                        item.OriginalContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        item.NewContext = item.OriginalContext;
                        item.ContextCaptured = TRUE;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
                return status;
            }
            inline NTSTATUS WriteDebugContextUserMode(TRANSACTION& t, THREAD_SNAPSHOT_ITEM& item,
                const CONTEXT& context)
            {
                if (!t.Attached || !t.Suspended || !item.ContextCaptured) return STATUS_INVALID_DEVICE_STATE;
                NTSTATUS status = STATUS_SUCCESS;
                __try
                {
                    auto user = static_cast<PCONTEXT>(t.UserContext.Address);
                    RtlCopyMemory(user, &context, sizeof(CONTEXT));
                    user->ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    status = PsSetContextThread(item.ThreadObject, user, UserMode);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
                return status;
            }
            inline NTSTATUS CaptureSelected(TRANSACTION& t)
            {
                for (ULONG i = 0; i < t.Count; ++i)
                {
                    if (!t.Items[i].Selected) continue;
                    NTSTATUS status = CaptureDebugContextUserMode(t, t.Items[i]);
                    if (!NT_SUCCESS(status)) return status;
                }
                return STATUS_SUCCESS;
            }
            inline NTSTATUS ApplySelected(TRANSACTION& t)
            {
                for (ULONG i = 0; i < t.Count; ++i)
                {
                    auto& item = t.Items[i];
                    if (!item.Selected) continue;
                    item.WriteAttempted = TRUE;
                    NTSTATUS status = WriteDebugContextUserMode(t, item, item.NewContext);
                    if (!NT_SUCCESS(status)) return status;
                }
                t.Committed = TRUE;
                return STATUS_SUCCESS;
            }
            inline NTSTATUS FinishTransaction(TRANSACTION& t, NTSTATUS status)
            {
                t.RollbackStatus = STATUS_SUCCESS;
                t.ResumeStatus = STATUS_SUCCESS;
                if (t.Suspended)
                {
                    if (!t.Committed)
                    {
                        for (ULONG n = t.Count; n != 0; --n)
                        {
                            auto& item = t.Items[n - 1];
                            if (!item.WriteAttempted) continue;
                            NTSTATUS rollback = WriteDebugContextUserMode(t, item, item.OriginalContext);
                            if (NT_SUCCESS(rollback)) item.WriteAttempted = FALSE;
                            RecordFailure(t.RollbackStatus, rollback);
                        }
                        if (!NT_SUCCESS(t.RollbackStatus)) status = STATUS_TRANSACTION_ABORTED;
                    }
                    t.ResumeStatus = PsResumeProcess(t.Target); // Exactly one balancing attempt.
                    t.Suspended = FALSE; // Resume was attempted; never retry silently in cleanup.
                    if (!NT_SUCCESS(t.ResumeStatus)) status = t.ResumeStatus;
                }
                if (t.Attached) { KeUnstackDetachProcess(&t.ApcState); t.Attached = FALSE; }
                UnlockUser(t.UserContext);
                RecordFailure(status, ReleaseUser(t.TargetHandle, t.UserContext.Address));
                t.UserContext.Address = nullptr;
                if (!NT_SUCCESS(t.RollbackStatus) || !NT_SUCCESS(t.ResumeStatus))
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[HWBP] PID=%p rollback=0x%08lX resume=0x%08lX\n",
                        PsGetProcessId(t.Target), static_cast<ULONG>(t.RollbackStatus),
                        static_cast<ULONG>(t.ResumeStatus));
                return status;
            }
            inline VOID CleanupTransaction(TRANSACTION& t)
            {
                // FinishTransaction must run first, even after BeginTransaction fails.
                CleanupThreadSnapshot(t.Items, t.Count);
                if (t.RequestHandle) ZwClose(t.RequestHandle);
                if (t.TargetHandle) ZwClose(t.TargetHandle);
                if (t.Request) ObDereferenceObject(t.Request);
                if (t.Target) ObDereferenceObject(t.Target);
            }
        }

        constexpr ULONGLONG HARDWARE_BREAKPOINT_RESULT_SIGNATURE = 0x4857425052455331ULL;
        typedef struct _HARDWARE_BREAKPOINT_THREAD_INFORMATION
        {
            ULONGLONG Signature;
            HANDLE ProcessId;
            HANDLE ThreadId;
            ULONG Slot;
            ULONG Reserved;
            PVOID Address;
            hwbp_internal::HARDWARE_BREAKPOINT_TYPE Type;
            hwbp_internal::HARDWARE_BREAKPOINT_LENGTH Length;
            ULONGLONG OriginalDrValue;
            ULONGLONG OriginalDr7SlotBits;
            ULONGLONG InstalledDr7;
        } HARDWARE_BREAKPOINT_THREAD_INFORMATION, * PHARDWARE_BREAKPOINT_THREAD_INFORMATION;

        typedef struct _HARDWARE_BREAKPOINT_QUERY_INFORMATION
        {
            HANDLE ProcessId;
            HANDLE ThreadId;
            ULONGLONG Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            ULONG EnabledSlotMask;
            ULONG EnabledBreakpointCount;
        } HARDWARE_BREAKPOINT_QUERY_INFORMATION, * PHARDWARE_BREAKPOINT_QUERY_INFORMATION;

        static_assert(sizeof(HARDWARE_BREAKPOINT_THREAD_INFORMATION) == 72, "HWBP Set ABI changed");
        static_assert(sizeof(HARDWARE_BREAKPOINT_QUERY_INFORMATION) == 72, "HWBP Query ABI changed");
        static_assert(sizeof(helper::linkedlist::LINKED_LIST_NODE) == 40, "Linked-list ABI changed");

        namespace hwbp_internal
        {
            struct RESULT_SLOT
            {
                LOCKED_USER_BUFFER Node;
                LOCKED_USER_BUFFER Data;
                BOOLEAN Keep;
            };
            // Separate node/data allocations preserve the existing generic list-free format.
            // Keep trusted allocation addresses: never follow user-modifiable pointers during cleanup.
            inline NTSTATUS PrepareResults(TRANSACTION& t, ULONG dataSize, RESULT_SLOT** output)
            {
                *output = static_cast<RESULT_SLOT*>(Allocate(sizeof(RESULT_SLOT) * t.Count));
                if (!*output) return STATUS_INSUFFICIENT_RESOURCES;
                for (ULONG i = 0; i < t.Count; ++i)
                {
                    auto& slot = (*output)[i];
                    NTSTATUS status = AllocateUser(t.RequestHandle, sizeof(helper::linkedlist::LINKED_LIST_NODE), &slot.Node.Address);
                    if (!NT_SUCCESS(status)) return status;
                    status = AllocateUser(t.RequestHandle, dataSize, &slot.Data.Address);
                    if (!NT_SUCCESS(status)) return status;
                    KAPC_STATE state = {};
                    KeStackAttachProcess(t.Request, &state);
                    __try
                    {
                        status = LockUser(slot.Node, sizeof(helper::linkedlist::LINKED_LIST_NODE));
                        if (NT_SUCCESS(status)) status = LockUser(slot.Data, dataSize);
                    }
                    __finally { KeUnstackDetachProcess(&state); }
                    if (!NT_SUCCESS(status)) return status;
                    RtlZeroMemory(slot.Data.Mapping, dataSize);
                    auto node = static_cast<helper::linkedlist::PLINKED_LIST_NODE>(slot.Node.Mapping);
                    RtlZeroMemory(node, sizeof(*node));
                    node->Signature = helper::linkedlist::LINKED_LIST_SIGNATURE;
                    node->Data = slot.Data.Address;
                    node->DataSize = dataSize;
                }
                return STATUS_SUCCESS;
            }
            inline NTSTATUS PublishAndReleaseResults(TRANSACTION& t, RESULT_SLOT* slots,
                PVOID* output, NTSTATUS status)
            {
                *output = nullptr;
                if (!slots) return status;
                helper::linkedlist::PLINKED_LIST_NODE previousMapping = nullptr;
                PVOID previousAddress = nullptr;
                for (ULONG i = 0; i < t.Count; ++i)
                {
                    auto& slot = slots[i];
                    if (!slot.Keep) continue;
                    auto node = static_cast<helper::linkedlist::PLINKED_LIST_NODE>(slot.Node.Mapping);
                    node->Previous = previousAddress;
                    node->Next = nullptr;
                    if (previousMapping) previousMapping->Next = slot.Node.Address;
                    else *output = slot.Node.Address;
                    previousMapping = node;
                    previousAddress = slot.Node.Address;
                }
                for (ULONG i = 0; i < t.Count; ++i)
                {
                    auto& slot = slots[i];
                    UnlockUser(slot.Data);
                    UnlockUser(slot.Node);
                    if (!slot.Keep)
                    {
                        RecordFailure(status, ReleaseUser(t.RequestHandle, slot.Data.Address));
                        RecordFailure(status, ReleaseUser(t.RequestHandle, slot.Node.Address));
                    }
                }
                Free(slots);
                return status;
            }

            struct INPUT_ENTRY
            {
                PVOID NodeAddress;
                helper::linkedlist::LINKED_LIST_NODE Node;
                HARDWARE_BREAKPOINT_THREAD_INFORMATION Information;
                ULONG ItemIndex;
                BOOLEAN AlreadyRestored;
            };
            // Copies the entire list before touching any thread. Bounded traversal rejects cycles,
            // duplicate node/data allocations, malformed links, and mixed payload sizes.
            inline NTSTATUS ReadResultList(PEPROCESS request, PVOID first, BOOLEAN removal,
                INPUT_ENTRY** output, PULONG count)
            {
                *count = 0;
                *output = static_cast<INPUT_ENTRY*>(Allocate(sizeof(INPUT_ENTRY) * MaximumEntries));
                if (!*output) return STATUS_INSUFFICIENT_RESOURCES;
                PVOID current = first;
                PVOID previous = nullptr;
                ULONGLONG payloadSize = 0;
                while (current)
                {
                    if (*count == MaximumEntries) return STATUS_INSUFFICIENT_RESOURCES;
                    auto& e = (*output)[*count];
                    e.NodeAddress = current;
                    e.ItemIndex = MAXULONG;
                    NTSTATUS status = STATUS_SUCCESS;
                    KAPC_STATE state = {};
                    KeStackAttachProcess(request, &state);
                    __try
                    {
                        ProbeForRead(current, sizeof(e.Node), __alignof(helper::linkedlist::LINKED_LIST_NODE));
                        RtlCopyMemory(&e.Node, current, sizeof(e.Node));
                        if (e.Node.Signature != helper::linkedlist::LINKED_LIST_SIGNATURE ||
                            e.Node.Previous != previous || !UserRange(e.Node.Data, static_cast<SIZE_T>(e.Node.DataSize)) ||
                            (e.Node.DataSize != sizeof(HARDWARE_BREAKPOINT_THREAD_INFORMATION) &&
                                e.Node.DataSize != sizeof(HARDWARE_BREAKPOINT_QUERY_INFORMATION)))
                            status = STATUS_DATA_ERROR;
                        if (NT_SUCCESS(status) && removal)
                        {
                            if (e.Node.DataSize != sizeof(e.Information)) status = STATUS_DATA_ERROR;
                            else
                            {
                                ProbeForRead(e.Node.Data, sizeof(e.Information), __alignof(HARDWARE_BREAKPOINT_THREAD_INFORMATION));
                                RtlCopyMemory(&e.Information, e.Node.Data, sizeof(e.Information));
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
                    KeUnstackDetachProcess(&state);
                    if (!NT_SUCCESS(status)) return status;
                    if (!payloadSize) payloadSize = e.Node.DataSize;
                    if (e.Node.DataSize != payloadSize || !UserRange(current, sizeof(e.Node)) ||
                        (reinterpret_cast<ULONG_PTR>(current) & (PAGE_SIZE - 1)) ||
                        (reinterpret_cast<ULONG_PTR>(e.Node.Data) & (PAGE_SIZE - 1)) || current == e.Node.Data)
                        return STATUS_DATA_ERROR;
                    for (ULONG j = 0; j < *count; ++j)
                    {
                        const auto& old = (*output)[j];
                        if (current == old.NodeAddress || current == old.Node.Data ||
                            e.Node.Data == old.NodeAddress || e.Node.Data == old.Node.Data)
                            return STATUS_DATA_ERROR;
                    }
                    ++ * count;
                    previous = current;
                    current = e.Node.Next;
                }
                return *count ? STATUS_SUCCESS : STATUS_NOT_FOUND;
            }
        }

        inline NTSTATUS SetHardwareBreakpoint(
            _In_ HANDLE request_process_handle, _In_ HANDLE target_process_handle,
            _In_ PVOID target_address, _In_ hwbp_internal::HARDWARE_BREAKPOINT_TYPE type,
            _In_ hwbp_internal::HARDWARE_BREAKPOINT_LENGTH length,
            _Out_ PVOID* output_first_result_node,
            _Out_opt_ PULONG applied_thread_count = nullptr,
            _Out_opt_ PULONG failed_thread_count = nullptr)
        {
            using namespace hwbp_internal;
            if (!output_first_result_node) return STATUS_INVALID_PARAMETER;
            *output_first_result_node = nullptr;
            if (applied_thread_count) *applied_thread_count = 0;
            if (failed_thread_count) *failed_thread_count = 0;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
            NTSTATUS status = ValidateBreakpoint(target_address, type, length);
            if (!NT_SUCCESS(status)) return status;
            if (InterlockedCompareExchange(OperationGate(), 1, 0)) return STATUS_DEVICE_BUSY;
            TRANSACTION t = {};
            RESULT_SLOT* results = nullptr;
            __try
            {
                do
                {
                    status = PrepareTransaction(t, request_process_handle, target_process_handle);
                    if (!NT_SUCCESS(status)) break;
                    status = PrepareResults(t, sizeof(HARDWARE_BREAKPOINT_THREAD_INFORMATION), &results);
                    if (!NT_SUCCESS(status)) break;
                    for (ULONG i = 0; i < t.Count; ++i) t.Items[i].Selected = TRUE;
                    status = BeginTransaction(t);
                    if (!NT_SUCCESS(status)) break;
                    status = CaptureSelected(t);
                    if (!NT_SUCCESS(status)) break;
                    for (ULONG i = 0; i < t.Count; ++i)
                    {
                        HARDWARE_BREAKPOINT_THREAD_INFORMATION info = {};
                        info.Signature = HARDWARE_BREAKPOINT_RESULT_SIGNATURE;
                        info.ProcessId = PsGetProcessId(t.Target);
                        info.ThreadId = t.Items[i].ThreadId;
                        info.Address = target_address;
                        info.Type = type;
                        info.Length = length;
                        status = BuildBreakpointContext(t.Items[i].OriginalContext, target_address, type, length,
                            &t.Items[i].NewContext, &info.Slot, &info.OriginalDrValue, &info.OriginalDr7SlotBits);
                        if (!NT_SUCCESS(status)) break;
                        info.InstalledDr7 = t.Items[i].NewContext.Dr7;
                        RtlCopyMemory(results[i].Data.Mapping, &info, sizeof(info));
                    }
                    if (!NT_SUCCESS(status)) break;
                    status = ApplySelected(t);
                } while (false);
            }
            __finally
            {
                status = FinishTransaction(t, status);
                ULONG retained = 0;
                if (results)
                {
                    for (ULONG i = 0; i < t.Count; ++i)
                    {
                        results[i].Keep = t.Committed || t.Items[i].WriteAttempted;
                        if (results[i].Keep) ++retained;
                    }
                }
                // Failed rollback returns recovery records even though ResultStatus is failure.
                status = PublishAndReleaseResults(t, results, output_first_result_node, status);
                if (applied_thread_count) *applied_thread_count = retained;
                if (failed_thread_count) *failed_thread_count = NT_SUCCESS(status) ? 0 : t.Count;
                CleanupTransaction(t);
                InterlockedExchange(OperationGate(), 0);
            }
            return status;
        }

        inline NTSTATUS QueryHardwareBreakpoints(
            _In_ HANDLE request_process_handle, _In_ HANDLE target_process_handle,
            _Out_ PVOID* output_first_result_node,
            _Out_opt_ PULONG output_thread_count = nullptr,
            _Out_opt_ PULONG output_breakpoint_count = nullptr)
        {
            using namespace hwbp_internal;
            if (!output_first_result_node) return STATUS_INVALID_PARAMETER;
            *output_first_result_node = nullptr;
            if (output_thread_count) *output_thread_count = 0;
            if (output_breakpoint_count) *output_breakpoint_count = 0;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
            if (InterlockedCompareExchange(OperationGate(), 1, 0)) return STATUS_DEVICE_BUSY;
            TRANSACTION t = {};
            RESULT_SLOT* results = nullptr;
            NTSTATUS status = STATUS_SUCCESS;
            ULONG breakpoints = 0;
            BOOLEAN captured = FALSE;
            __try
            {
                do
                {
                    status = PrepareTransaction(t, request_process_handle, target_process_handle);
                    if (!NT_SUCCESS(status)) break;
                    status = PrepareResults(t, sizeof(HARDWARE_BREAKPOINT_QUERY_INFORMATION), &results);
                    if (!NT_SUCCESS(status)) break;
                    for (ULONG i = 0; i < t.Count; ++i) t.Items[i].Selected = TRUE;
                    status = BeginTransaction(t);
                    if (!NT_SUCCESS(status)) break;
                    status = CaptureSelected(t);
                    if (!NT_SUCCESS(status)) break;
                    for (ULONG i = 0; i < t.Count; ++i)
                    {
                        HARDWARE_BREAKPOINT_QUERY_INFORMATION info = {};
                        const auto& c = t.Items[i].OriginalContext;
                        info.ProcessId = PsGetProcessId(t.Target);
                        info.ThreadId = t.Items[i].ThreadId;
                        info.Dr0 = c.Dr0; info.Dr1 = c.Dr1; info.Dr2 = c.Dr2;
                        info.Dr3 = c.Dr3; info.Dr6 = c.Dr6; info.Dr7 = c.Dr7;
                        for (ULONG s = 0; s < 4; ++s)
                            if (IsSlotEnabled(c.Dr7, s))
                            {
                                info.EnabledSlotMask |= 1UL << s; ++info.EnabledBreakpointCount; ++breakpoints;
                            }
                        RtlCopyMemory(results[i].Data.Mapping, &info, sizeof(info));
                    }
                    captured = TRUE;
                } while (false);
            }
            __finally
            {
                status = FinishTransaction(t, status);
                if (results) for (ULONG i = 0; i < t.Count; ++i) results[i].Keep = captured;
                status = PublishAndReleaseResults(t, results, output_first_result_node, status);
                if (captured)
                {
                    if (output_thread_count) *output_thread_count = t.Count;
                    if (output_breakpoint_count) *output_breakpoint_count = breakpoints;
                }
                CleanupTransaction(t);
                InterlockedExchange(OperationGate(), 0);
            }
            return status;
        }

        inline NTSTATUS RemoveHardwareBreakpoint(
            _In_ HANDLE request_process_handle, _In_ HANDLE target_process_handle,
            _In_ PVOID first_result_node,
            _Out_opt_ PULONG removed_thread_count = nullptr,
            _Out_opt_ PULONG failed_thread_count = nullptr)
        {
            using namespace hwbp_internal;
            if (removed_thread_count) *removed_thread_count = 0;
            if (failed_thread_count) *failed_thread_count = 0;
            if (!first_result_node) return STATUS_INVALID_PARAMETER;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
            if (InterlockedCompareExchange(OperationGate(), 1, 0)) return STATUS_DEVICE_BUSY;
            TRANSACTION t = {};
            INPUT_ENTRY* entries = nullptr;
            ULONG entryCount = 0;
            ULONG absent = 0;
            ULONG restored = 0;
            BOOLEAN validated = FALSE;
            NTSTATUS status = STATUS_SUCCESS;
            __try
            {
                do
                {
                    status = PrepareTransaction(t, request_process_handle, target_process_handle);
                    if (!NT_SUCCESS(status)) break;
                    status = ReadResultList(t.Request, first_result_node, TRUE, &entries, &entryCount);
                    if (!NT_SUCCESS(status)) break;
                    if (t.Target == nullptr || t.Items == nullptr || entries == nullptr)
                    {
                        status = STATUS_INVALID_DEVICE_STATE;
                        break;
                    }
                    for (ULONG n = 0; n < entryCount; ++n)
                    {
                        auto& e = entries[n];
                        const auto& info = e.Information;
                        if (info.Signature != HARDWARE_BREAKPOINT_RESULT_SIGNATURE || info.Reserved != 0 ||
                            info.ProcessId != PsGetProcessId(t.Target) || !info.ThreadId || info.Slot >= 4 ||
                            !NT_SUCCESS(ValidateBreakpoint(info.Address, info.Type, info.Length)) ||
                            info.OriginalDrValue != 0 || (info.OriginalDr7SlotBits & ~GetDr7ConditionMask(info.Slot)))
                        {
                            status = STATUS_DATA_ERROR; break;
                        }
                        ULONGLONG expected = 0;
                        ConfigureDr7Slot(expected, info.Slot, info.Type, info.Length);
                        if (ExtractDr7SlotBits(info.InstalledDr7, info.Slot) != expected)
                        {
                            status = STATUS_DATA_ERROR; break;
                        }
                        for (ULONG j = 0; j < n; ++j)
                            if (entries[j].Information.ThreadId == info.ThreadId)
                            {
                                status = STATUS_DATA_ERROR; break;
                            }
                        if (!NT_SUCCESS(status)) break;
                        for (ULONG i = 0; i < t.Count; ++i)
                            if (t.Items[i].ThreadId == info.ThreadId)
                            {
                                e.ItemIndex = i; t.Items[i].Selected = TRUE; break;
                            }
                        if (e.ItemIndex == MAXULONG)
                        {
                            // Missing from a pre-suspend snapshot is not proof of exit.
                            PETHREAD thread = nullptr;
                            NTSTATUS lookup = PsLookupThreadByThreadId(info.ThreadId, &thread);
                            if (NT_SUCCESS(lookup))
                            {
                                const BOOLEAN gone = PsIsThreadTerminating(thread);
                                ObDereferenceObject(thread);
                                if (!gone) { status = STATUS_INVALID_CID; break; }
                            }
                            else if (lookup != STATUS_INVALID_CID && lookup != STATUS_THREAD_IS_TERMINATING)
                            {
                                status = lookup; break;
                            }
                            ++absent;
                        }
                    }
                    if (!NT_SUCCESS(status)) break;
                    status = BeginTransaction(t);
                    if (!NT_SUCCESS(status)) break;
                    status = CaptureSelected(t);
                    if (!NT_SUCCESS(status)) break;
                    for (ULONG n = 0; n < entryCount; ++n)
                    {
                        auto& e = entries[n];
                        if (e.ItemIndex == MAXULONG) continue;
                        auto& item = t.Items[e.ItemIndex];
                        const auto& info = e.Information;
                        const auto& c = item.OriginalContext;
                        // Makes retry of a partially restored result list possible.
                        if (GetDrValue(c, info.Slot) == info.OriginalDrValue &&
                            ExtractDr7SlotBits(c.Dr7, info.Slot) == info.OriginalDr7SlotBits)
                        {
                            e.AlreadyRestored = TRUE; item.Selected = FALSE; ++restored; continue;
                        }
                        if (!VerifyInstalledBreakpoint(c, info.Slot, info.Address, info.Type, info.Length) ||
                            ExtractDr7SlotBits(c.Dr7, info.Slot) != ExtractDr7SlotBits(info.InstalledDr7, info.Slot))
                        {
                            status = STATUS_DATA_ERROR; break;
                        }
                        status = BuildRestoreContext(c, info.Slot, info.OriginalDrValue,
                            info.OriginalDr7SlotBits, &item.NewContext);
                        if (!NT_SUCCESS(status)) break;
                    }
                    if (!NT_SUCCESS(status)) break;
                    validated = TRUE;
                    status = ApplySelected(t);
                } while (false);
            }
            __finally
            {
                status = FinishTransaction(t, status);
                // Uncertain failed-rollback writes are not counted as confirmed removals.
                ULONG done = t.Committed ? entryCount : (validated ? absent + restored : 0);
                if (removed_thread_count) *removed_thread_count = done;
                if (failed_thread_count) *failed_thread_count = entryCount - done;
                Free(entries);
                CleanupTransaction(t);
                InterlockedExchange(OperationGate(), 0);
            }
            return status;
        }

        inline NTSTATUS FreeHardwareBreakpointResult(
            _In_ HANDLE request_process_handle, _In_opt_ PVOID first_result_node)
        {
            using namespace hwbp_internal;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
            if (!request_process_handle) return STATUS_INVALID_PARAMETER;
            if (!first_result_node) return STATUS_SUCCESS;
            if (InterlockedCompareExchange(OperationGate(), 1, 0)) return STATUS_DEVICE_BUSY;
            PEPROCESS request = nullptr;
            HANDLE handle = nullptr;
            INPUT_ENTRY* entries = nullptr;
            ULONG count = 0;
            NTSTATUS status = STATUS_SUCCESS;
            __try
            {
                do
                {
                    status = OpenReferencedProcess(request_process_handle, &request, &handle);
                    if (!NT_SUCCESS(status)) break;
                    status = ReadResultList(request, first_result_node, FALSE, &entries, &count);
                    if (!NT_SUCCESS(status)) break;
                    // Validate everything before freeing the first allocation. No HWBP changes here.
                    for (ULONG i = 0; i < count; ++i)
                    {
                        RecordFailure(status, ReleaseUser(handle, entries[i].Node.Data));
                        RecordFailure(status, ReleaseUser(handle, entries[i].NodeAddress));
                    }
                } while (false);
            }
            __finally
            {
                Free(entries);
                if (handle) ZwClose(handle);
                if (request) ObDereferenceObject(request);
                InterlockedExchange(OperationGate(), 0);
            }
            return status;
        }



        inline VOID CloseHandle(
            _In_ HANDLE handle
        )
        {
            if (handle == nullptr)
                return;

            ZwClose(handle);
        }

        inline NTSTATUS PIDtoHANDLE(
            _In_ HANDLE pid,
            _Out_ PHANDLE handle
        )
        {
            if (pid == nullptr || handle == nullptr)
                return STATUS_INVALID_PARAMETER;

            *handle = nullptr;

            PEPROCESS process = nullptr;

            NTSTATUS status = PsLookupProcessByProcessId(
                pid,
                &process
            );

            if (!NT_SUCCESS(status))
                return status;

            status = ObOpenObjectByPointer(
                process,
                OBJ_KERNEL_HANDLE,
                nullptr,
                PROCESS_QUERY_INFORMATION,
                *PsProcessType,
                KernelMode,
                handle
            );

            ObDereferenceObject(process);

            return status;
        }


        typedef struct _ACTIVE_PROCESS_INFORMATION
        {
            HANDLE ProcessId;
            HANDLE ParentProcessId;

            PEPROCESS ProcessObject;

            PPEB PebBaseAddress;

            NTSTATUS ExitStatus;

            ULONG_PTR AffinityMask;
            KPRIORITY BasePriority;

            ULONGLONG ProcessStartKey;

            BOOLEAN IsProtectedProcess;

            //
            // SeLocateProcessImageName() allocated buffer.
            //
            PUNICODE_STRING ImageFileName;

        } ACTIVE_PROCESS_INFORMATION, * PACTIVE_PROCESS_INFORMATION;


		// SearchActiveProcessInformation()를 사전에 호출한 후, 사용이 끝나면 반드시 호출해야 한다.
        inline VOID FreeActiveProcessInformation(
            _Inout_ PACTIVE_PROCESS_INFORMATION process_information
        )
        {
            if (process_information == nullptr)
                return;

            if (process_information->ImageFileName != nullptr)
            {
                ExFreePool(
                    process_information->ImageFileName
                );

                process_information->ImageFileName = nullptr;
            }

            //
            // SearchActiveProcessInformation() keeps a reference
            // to EPROCESS for the caller.
            //
            if (process_information->ProcessObject != nullptr)
            {
                ObDereferenceObject(
                    process_information->ProcessObject
                );

                process_information->ProcessObject = nullptr;
            }
        }

		// 프로세스 정보를 검색하고, 검색된 정보를 process_information에 채워 output한다.
        inline NTSTATUS SearchActiveProcessInformation(
            _In_ HANDLE pid,
            _Out_ PACTIVE_PROCESS_INFORMATION process_information
        )
        {
            if (
                pid == nullptr ||
                process_information == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }

            //
            // SeLocateProcessImageName requires PASSIVE_LEVEL.
            //
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            RtlZeroMemory(
                process_information,
                sizeof(ACTIVE_PROCESS_INFORMATION)
            );

            PEPROCESS process = nullptr;

            NTSTATUS status = PsLookupProcessByProcessId(
                pid,
                &process
            );

            if (!NT_SUCCESS(status))
                return status;


            //
            // -----------------------------------------
            // Basic information
            // -----------------------------------------
            //

            process_information->ProcessId =
                PsGetProcessId(process);

            process_information->ProcessObject =
                process;

            process_information->ProcessStartKey =
                PsGetProcessStartKey(process);

            process_information->IsProtectedProcess =
                PsIsProtectedProcess(process);


            //
            // -----------------------------------------
            // Full executable image path
            // -----------------------------------------
            //

            PUNICODE_STRING image_file_name = nullptr;

            status = SeLocateProcessImageName(
                process,
                &image_file_name
            );

            if (NT_SUCCESS(status))
            {
                process_information->ImageFileName =
                    image_file_name;
            }
            else
            {
                //
                // Image path failure should not make the
                // entire process query fail.
                //
                process_information->ImageFileName = nullptr;
            }


            //
            // -----------------------------------------
            // Query PROCESS_BASIC_INFORMATION
            // -----------------------------------------
            //

            HANDLE process_handle = nullptr;

            status = ObOpenObjectByPointer(
                process,
                OBJ_KERNEL_HANDLE,
                nullptr,
                PROCESS_QUERY_INFORMATION,
                *PsProcessType,
                KernelMode,
                &process_handle
            );

            if (NT_SUCCESS(status))
            {
                PROCESS_BASIC_INFORMATION basic_information = {};

                ULONG return_length = 0;

                NTSTATUS query_status = ZwQueryInformationProcess(
                    process_handle,
                    ProcessBasicInformation,
                    &basic_information,
                    sizeof(basic_information),
                    &return_length
                );

                if (NT_SUCCESS(query_status))
                {
                    process_information->ParentProcessId =
                        reinterpret_cast<HANDLE>(
                            basic_information.InheritedFromUniqueProcessId
                            );

                    process_information->PebBaseAddress =
                        basic_information.PebBaseAddress;

                    process_information->ExitStatus =
                        basic_information.ExitStatus;

                    process_information->AffinityMask =
                        basic_information.AffinityMask;

                    process_information->BasePriority =
                        basic_information.BasePriority;
                }

                ZwClose(
                    process_handle
                );

                return STATUS_SUCCESS;
            }
            return STATUS_UNSUCCESSFUL;
        }

        typedef struct _DLL_REGISTER_INFORMATION
        {
            HANDLE ProcessId;

            BOOLEAN TargetIsWow64;
            BOOLEAN Kernel32Found;
            BOOLEAN LoadLibraryFound;

            PVOID Kernel32Base;
            SIZE_T Kernel32Size;

            PVOID LoadLibraryAddress;

            WCHAR DllPath[520];

        } DLL_REGISTER_INFORMATION,
        *PDLL_REGISTER_INFORMATION;


        struct DLL_CLEANUP_TASK
        {
            LIST_ENTRY Entry;
            HANDLE WorkerHandle;
            HANDLE ProcessHandle;
            PETHREAD RemoteThread;
            PVOID Path;
            KEVENT Ready;
        };
        struct DLL_CLEANUP_STATE
        {
            KMUTEX Mutex;
            LIST_ENTRY Tasks;
        };
        inline DLL_CLEANUP_STATE& DllCleanupState()
        {
            static DLL_CLEANUP_STATE state = {};
            return state;
        }
        inline VOID InitializeDllCleanup()
        {
            auto& state = DllCleanupState();
            KeInitializeMutex(&state.Mutex, 0);
            InitializeListHead(&state.Tasks);
        }
        inline VOID DllCleanupWorker(PVOID context)
        {
            auto task = static_cast<DLL_CLEANUP_TASK*>(context);
            KeWaitForSingleObject(&task->Ready, Executive, KernelMode, FALSE, nullptr);
            if (task->RemoteThread)
            {
                KeWaitForSingleObject(task->RemoteThread, Executive, KernelMode, FALSE, nullptr);
                ObDereferenceObject(task->RemoteThread);
            }
            if (task->Path)
                helper::allocate::usermode::FreeVirtualMemory(task->ProcessHandle, task->Path);
            ZwClose(task->ProcessHandle);
            // The task and worker handle are freed by ReapDllCleanup after
            // this thread has terminated, so unload cannot race this code.
            PsTerminateSystemThread(STATUS_SUCCESS);
        }
        inline VOID ReapDllCleanup(BOOLEAN wait_for_all = FALSE)
        {
            auto& state = DllCleanupState();
            KeWaitForSingleObject(&state.Mutex, Executive, KernelMode, FALSE, nullptr);
            auto entry = state.Tasks.Flink;
            LARGE_INTEGER zero = {};
            while (entry != &state.Tasks)
            {
                auto task = CONTAINING_RECORD(entry, DLL_CLEANUP_TASK, Entry);
                entry = entry->Flink;
                NTSTATUS status = ZwWaitForSingleObject(task->WorkerHandle, FALSE,
                    wait_for_all ? nullptr : &zero);
                if (status == STATUS_SUCCESS)
                {
                    RemoveEntryList(&task->Entry);
                    ZwClose(task->WorkerHandle);
                    helper::allocate::kernelmode::FreeKernelMemory(task);
                }
            }
            KeReleaseMutex(&state.Mutex, FALSE);
        }

        inline NTSTATUS DllRegister(
            _In_ HANDLE process_handle,
            _In_ PCUNICODE_STRING dll_path,
            _Out_ PDLL_REGISTER_INFORMATION information
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            if (
                process_handle == nullptr ||
                dll_path == nullptr ||
                information == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }

            if (
                dll_path->Buffer == nullptr ||
                dll_path->Length == 0
                )
            {
                return STATUS_INVALID_PARAMETER;
            }

            RtlZeroMemory(
                information,
                sizeof(DLL_REGISTER_INFORMATION)
            );

            //
            // Resolve target EPROCESS.
            //
            PEPROCESS process = nullptr;

            NTSTATUS status =
                ObReferenceObjectByHandle(
                    process_handle,
                    PROCESS_QUERY_INFORMATION,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(&process),
                    nullptr
                );

            if (!NT_SUCCESS(status))
                return status;

            information->ProcessId =
                PsGetProcessId(process);

            information->TargetIsWow64 =
                (
                    PsGetProcessWow64Process(process) !=
                    nullptr
                    );

            //
            // Copy the supplied path into our result structure.
            //
            USHORT copy_length = dll_path->Length;
            const USHORT maximum_copy = static_cast<USHORT>(sizeof(information->DllPath) - sizeof(WCHAR));

            if (copy_length > maximum_copy)
                copy_length = maximum_copy;

            RtlCopyMemory(
                information->DllPath,
                dll_path->Buffer,
                copy_length
            );

            information->DllPath[copy_length / sizeof(WCHAR)] = L'\0';

            //
            // ========================================================
            // Target Process PEB / LDR inspection
            // ========================================================
            //
            PPEB peb = PsGetProcessPeb(process);
            if (peb == nullptr)
            {
                ObDereferenceObject(process);
                return STATUS_NOT_FOUND;
            }

            KAPC_STATE apc_state = {};
            BOOLEAN attached = FALSE;

            __try
            {
                KeStackAttachProcess(process, &apc_state);
                attached = TRUE;

                if (peb->Ldr == nullptr || peb->Ldr->InMemoryOrderModuleList.Flink == nullptr)
                {
                    status = STATUS_NOT_FOUND;
                    __leave;
                }

                UNICODE_STRING kernel32_name = {};
                RtlInitUnicodeString(&kernel32_name, L"kernel32.dll");

                PLIST_ENTRY list_head = &peb->Ldr->InMemoryOrderModuleList;
                PLIST_ENTRY current = list_head->Flink;

                while (current != list_head)
                {
                    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
                        current,
                        LDR_DATA_TABLE_ENTRY,
                        InMemoryOrderLinks
                    );

                    if (entry->BaseDllName.Buffer != nullptr)
                    {
                        if (RtlEqualUnicodeString(&entry->BaseDllName, &kernel32_name, TRUE))
                        {
                            information->Kernel32Found = TRUE;
                            information->Kernel32Base = entry->DllBase;
                            information->Kernel32Size = entry->SizeOfImage;

                            //
                            // ========================================
                            // PE export parsing
                            // ========================================
                            //
                            PUCHAR image_base = static_cast<PUCHAR>(entry->DllBase);
                            PHELPER_IMAGE_DOS_HEADER dos = reinterpret_cast<PHELPER_IMAGE_DOS_HEADER>(image_base);

                            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                            {
                                status = STATUS_INVALID_IMAGE_FORMAT;
                                __leave;
                            }

                            PHELPER_IMAGE_NT_HEADERS64 nt = reinterpret_cast<PHELPER_IMAGE_NT_HEADERS64>(image_base + dos->e_lfanew);

                            if (nt->Signature != IMAGE_NT_SIGNATURE)
                            {
                                status = STATUS_INVALID_IMAGE_FORMAT;
                                __leave;
                            }

                            const HELPER_IMAGE_DATA_DIRECTORY& export_directory_entry =
                                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                            if (export_directory_entry.VirtualAddress == 0 || export_directory_entry.Size == 0)
                            {
                                status = STATUS_NOT_FOUND;
                                __leave;
                            }

                            PHELPER_IMAGE_EXPORT_DIRECTORY exports = reinterpret_cast<PHELPER_IMAGE_EXPORT_DIRECTORY>(
                                image_base + export_directory_entry.VirtualAddress
                                );

                            PULONG names = reinterpret_cast<PULONG>(image_base + exports->AddressOfNames);
                            PUSHORT ordinals = reinterpret_cast<PUSHORT>(image_base + exports->AddressOfNameOrdinals);
                            PULONG functions = reinterpret_cast<PULONG>(image_base + exports->AddressOfFunctions);

                            for (ULONG index = 0; index < exports->NumberOfNames; ++index)
                            {
                                PCSTR function_name = reinterpret_cast<PCSTR>(image_base + names[index]);

                                if (strcmp(function_name, "LoadLibraryW") == 0)
                                {
                                    const USHORT ordinal = ordinals[index];
                                    const ULONG function_rva = functions[ordinal];

                                    information->LoadLibraryAddress = image_base + function_rva;
                                    information->LoadLibraryFound = TRUE;

                                    status = STATUS_SUCCESS;
                                    __leave;
                                }
                            }

                            status = STATUS_NOT_FOUND;
                            __leave;
                        }
                    }

                    current = current->Flink;
                }

                status = STATUS_NOT_FOUND;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }

            if (attached)
            {
                KeUnstackDetachProcess(&apc_state);
            }

            if (!NT_SUCCESS(status) || !information->LoadLibraryFound)
            {
                ObDereferenceObject(process);
                return status;
            }

            //
            // ========================================================
            // Injection boundary
            // ========================================================
            //

            //
            // 1. 타겟 프로세스에 대한 전체 권한의 커널 핸들 생성
            // (넘겨받은 핸들의 권한 부족으로 인한 실패 방지)
            //
            HANDLE target_kernel_handle = nullptr;
            status = ObOpenObjectByPointer(
                process,
                OBJ_KERNEL_HANDLE,
                nullptr,
                PROCESS_ALL_ACCESS,
                *PsProcessType,
                KernelMode,
                &target_kernel_handle
            );

            if (!NT_SUCCESS(status))
            {
                ObDereferenceObject(process);
                return status;
            }

            //
            // 2. 타겟 프로세스에 DLL 경로 버퍼 할당
            //
            SIZE_T path_buffer_size = (wcslen(information->DllPath) + 1) * sizeof(WCHAR);
            PVOID target_path_buffer = nullptr;

            status = helper::allocate::usermode::AllocVirtualMemory(
                target_kernel_handle,
                path_buffer_size,
                PAGE_READWRITE,
                &target_path_buffer
            );

            if (!NT_SUCCESS(status))
            {
                ZwClose(target_kernel_handle);
                ObDereferenceObject(process);
                return status;
            }

            //
            // 3. DLL 경로 문자열을 타겟 프로세스 가상 메모리로 복사
            // (MmCopyVirtualMemory 활용)
            //
            SIZE_T bytes_copied = 0;
            status = MmCopyVirtualMemory(
                PsGetCurrentProcess(),
                information->DllPath,
                process,
                target_path_buffer,
                path_buffer_size,
                KernelMode,
                &bytes_copied
            );

            if (!NT_SUCCESS(status) || bytes_copied != path_buffer_size)
            {
                helper::allocate::usermode::FreeVirtualMemory(
                    target_kernel_handle,
                    target_path_buffer
                );
                ZwClose(target_kernel_handle);
                ObDereferenceObject(process);
                return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
            }

            // Reserve cleanup before launching the remote thread. Its path
            // must remain valid after the five-second IOCTL wait expires.
            auto cleanup = static_cast<DLL_CLEANUP_TASK*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DLL_CLEANUP_TASK), 'KmHA'));
            if (!cleanup)
            {
                helper::allocate::usermode::FreeVirtualMemory(target_kernel_handle, target_path_buffer);
                ZwClose(target_kernel_handle);
                ObDereferenceObject(process);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            cleanup->ProcessHandle = target_kernel_handle;
            cleanup->Path = target_path_buffer;
            KeInitializeEvent(&cleanup->Ready, NotificationEvent, FALSE);
            OBJECT_ATTRIBUTES attributes;
            InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
            status = PsCreateSystemThread(&cleanup->WorkerHandle, SYNCHRONIZE, &attributes,
                nullptr, nullptr, DllCleanupWorker, cleanup);
            if (!NT_SUCCESS(status))
            {
                helper::allocate::kernelmode::FreeKernelMemory(cleanup);
                helper::allocate::usermode::FreeVirtualMemory(target_kernel_handle, target_path_buffer);
                ZwClose(target_kernel_handle);
                ObDereferenceObject(process);
                return status;
            }
            auto& cleanup_state = DllCleanupState();
            KeWaitForSingleObject(&cleanup_state.Mutex, Executive, KernelMode, FALSE, nullptr);
            InsertTailList(&cleanup_state.Tasks, &cleanup->Entry);
            KeReleaseMutex(&cleanup_state.Mutex, FALSE);

            HANDLE thread_handle = nullptr;
            CLIENT_ID client_id = {};
            status = RtlCreateUserThread(target_kernel_handle, nullptr, FALSE, 0, 0, 0,
                reinterpret_cast<PUSER_THREAD_START_ROUTINE>(information->LoadLibraryAddress),
                target_path_buffer, &thread_handle, &client_id);
            if (NT_SUCCESS(status) && thread_handle != nullptr)
            {
                NTSTATUS reference_status = ObReferenceObjectByHandle(thread_handle, SYNCHRONIZE,
                    *PsThreadType, KernelMode, reinterpret_cast<PVOID*>(&cleanup->RemoteThread), nullptr);
                LARGE_INTEGER timeout;
                timeout.QuadPart = -50000000LL;
                NTSTATUS wait_status = ZwWaitForSingleObject(thread_handle, FALSE, &timeout);
                if (!NT_SUCCESS(reference_status) && wait_status != STATUS_SUCCESS)
                {
                    // Without a referenced thread there is no safe completion
                    // point. The target process owns this exceptional buffer
                    // until exit; never free memory a live thread may read.
                    cleanup->Path = nullptr;
                    status = reference_status;
                }
                ZwClose(thread_handle);
            }
            KeSetEvent(&cleanup->Ready, IO_NO_INCREMENT, FALSE);
            ObDereferenceObject(process);

            return status;
        }

#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME (0x0002)
#endif
#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#endif

        typedef struct _THREAD_ENTRY_INFO
        {
            HANDLE ThreadId;
            PVOID StartAddress;
            KPRIORITY Priority;
            LONG BasePriority;
            ULONG State;
            ULONG WaitReason;
            ULONG ContextSwitches;
        } THREAD_ENTRY_INFO, *PTHREAD_ENTRY_INFO;

        inline NTSTATUS EnumerateThreads(
            _In_ HANDLE target_process_id,
            _Out_writes_to_(max_threads, *thread_count) PTHREAD_ENTRY_INFO output_threads,
            _In_ ULONG max_threads,
            _Out_ PULONG thread_count
        )
        {
            if (output_threads == nullptr || max_threads == 0 || thread_count == nullptr)
                return STATUS_INVALID_PARAMETER;

            *thread_count = 0;

            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PVOID buffer = nullptr;
            ULONG size = 0x10000;
            ULONG returned = 0;
            NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

            for (ULONG retry = 0; retry < 10; ++retry)
            {
                buffer = helper::allocate::kernelmode::AllocateKernelMemory(size);
                if (buffer == nullptr)
                    return STATUS_INSUFFICIENT_RESOURCES;

                status = ZwQuerySystemInformation(SystemProcessInformation, buffer, size, &returned);
                if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
                    break;

                helper::allocate::kernelmode::FreeKernelMemory(buffer);
                buffer = nullptr;
                size = (returned > size) ? (returned + 0x2000) : (size * 2);
            }

            if (!NT_SUCCESS(status) || buffer == nullptr)
            {
                if (buffer != nullptr)
                    helper::allocate::kernelmode::FreeKernelMemory(buffer);
                return status;
            }

            const SIZE_T bytes = (returned && returned <= size) ? returned : size;
            SIZE_T offset = 0;
            ULONG found_count = 0;

            while (offset < bytes)
            {
                auto info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(static_cast<PUCHAR>(buffer) + offset);
                if (info->UniqueProcessId == target_process_id)
                {
                    ULONG count = info->NumberOfThreads;
                    if (count > max_threads)
                        count = max_threads;

                    for (ULONG i = 0; i < count; ++i)
                    {
                        output_threads[i].ThreadId = info->Threads[i].ClientId.UniqueThread;
                        output_threads[i].StartAddress = info->Threads[i].StartAddress;
                        output_threads[i].Priority = info->Threads[i].Priority;
                        output_threads[i].BasePriority = info->Threads[i].BasePriority;
                        output_threads[i].State = info->Threads[i].ThreadState;
                        output_threads[i].WaitReason = info->Threads[i].WaitReason;
                        output_threads[i].ContextSwitches = info->Threads[i].ContextSwitches;
                    }
                    found_count = count;
                    break;
                }

                if (!info->NextEntryOffset)
                    break;
                offset += info->NextEntryOffset;
            }

            helper::allocate::kernelmode::FreeKernelMemory(buffer);
            *thread_count = found_count;
            return STATUS_SUCCESS;
        }

        inline NTSTATUS SuspendThread(
            _In_ HANDLE thread_id,
            _Out_opt_ PULONG previous_suspend_count
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            HANDLE thread_handle = nullptr;
            status = ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_ALL_ACCESS,
                *PsThreadType,
                KernelMode,
                &thread_handle
            );

            if (NT_SUCCESS(status))
            {
                status = ZwSuspendThread(thread_handle, previous_suspend_count);
                ZwClose(thread_handle);
            }

            ObDereferenceObject(thread);
            return status;
        }

        inline NTSTATUS ResumeThread(
            _In_ HANDLE thread_id,
            _Out_opt_ PULONG previous_suspend_count
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            HANDLE thread_handle = nullptr;
            status = ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_ALL_ACCESS,
                *PsThreadType,
                KernelMode,
                &thread_handle
            );

            if (NT_SUCCESS(status))
            {
                status = ZwResumeThread(thread_handle, previous_suspend_count);
                ZwClose(thread_handle);
            }

            ObDereferenceObject(thread);
            return status;
        }

        inline NTSTATUS TransferThreadContext(PETHREAD thread, PCONTEXT context, BOOLEAN set)
        {
            hwbp_internal::LOCKED_USER_BUFFER buffer = {};
            NTSTATUS status = hwbp_internal::AllocateUser(NtCurrentProcess(), sizeof(CONTEXT), &buffer.Address);
            if (!NT_SUCCESS(status)) return status;
            __try
            {
                status = hwbp_internal::LockUser(buffer, sizeof(CONTEXT));
                if (NT_SUCCESS(status) && buffer.Mapping == nullptr)
                    status = STATUS_INSUFFICIENT_RESOURCES;
                if (NT_SUCCESS(status))
                {
                    RtlCopyMemory(buffer.Mapping, context, sizeof(CONTEXT));
                    auto user_context = static_cast<PCONTEXT>(buffer.Address);
                    status = set ? PsSetContextThread(thread, user_context, UserMode)
                        : PsGetContextThread(thread, user_context, UserMode);
                    if (NT_SUCCESS(status) && !set)
                        RtlCopyMemory(context, buffer.Mapping, sizeof(CONTEXT));
                }
            }
            __finally
            {
                hwbp_internal::UnlockUser(buffer);
                hwbp_internal::RecordFailure(status,
                    hwbp_internal::ReleaseUser(NtCurrentProcess(), buffer.Address));
            }
            return status;
        }

        inline NTSTATUS GetThreadContext(
            _In_ HANDLE thread_id,
            _Inout_ PCONTEXT context
        )
        {
            if (context == nullptr)
                return STATUS_INVALID_PARAMETER;

            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            status = TransferThreadContext(thread, context, FALSE);

            ObDereferenceObject(thread);
            return status;
        }

        inline NTSTATUS SetThreadContext(
            _In_ HANDLE thread_id,
            _In_ PCONTEXT context
        )
        {
            if (context == nullptr)
                return STATUS_INVALID_PARAMETER;

            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            status = TransferThreadContext(thread, context, TRUE);

            ObDereferenceObject(thread);
            return status;
        }

        typedef struct _PROCESS_EXTENDED_INFO
        {
            ULONGLONG ProcessId;
            ULONGLONG ParentProcessId;
            ULONGLONG PebBaseAddress;
            ULONGLONG AffinityMask;
            LONG BasePriority;
            NTSTATUS ExitStatus;
            ULONG SessionId;
            ULONG HandleCount;
            ULONG ThreadCount;
            ULONG IsWow64;
            ULONG IsProtectedProcess;

            LARGE_INTEGER CreateTime;
            LARGE_INTEGER ExitTime;
            LARGE_INTEGER KernelTime;
            LARGE_INTEGER UserTime;

            ULONGLONG PeakVirtualSize;
            ULONGLONG VirtualSize;
            ULONG PageFaultCount;
            ULONGLONG PeakWorkingSetSize;
            ULONGLONG WorkingSetSize;
            ULONGLONG QuotaPagedPoolUsage;
            ULONGLONG QuotaNonPagedPoolUsage;
            ULONGLONG PagefileUsage;
            ULONGLONG PeakPagefileUsage;
            ULONGLONG PrivateUsage;

            WCHAR ImageFileName[260];
            WCHAR CommandLine[512];
        } PROCESS_EXTENDED_INFO, *PPROCESS_EXTENDED_INFO;

        typedef struct _PROCESS_HANDLE_ENTRY
        {
            ULONGLONG HandleValue;
            ULONG ObjectTypeIndex;
            ULONG GrantedAccess;
            ULONGLONG ObjectPointer;
        } PROCESS_HANDLE_ENTRY, *PPROCESS_HANDLE_ENTRY;

        typedef struct _PROCESS_TOKEN_INFO
        {
            ULONGLONG ProcessId;
            ULONG TokenType;
            ULONG ElevationType;
            ULONG IsElevated;
            ULONG IntegrityLevel;
            ULONG SessionId;
            ULONG PrivilegeCount;
            ULONGLONG EnabledPrivilegesMask;
        } PROCESS_TOKEN_INFO, *PPROCESS_TOKEN_INFO;

        typedef struct _THREAD_EXTENDED_INFO
        {
            ULONGLONG ProcessId;
            ULONGLONG ThreadId;
            NTSTATUS ExitStatus;
            ULONGLONG TebBaseAddress;
            ULONGLONG StartAddress;
            ULONGLONG Win32StartAddress;
            LONG Priority;
            LONG BasePriority;
            ULONGLONG AffinityMask;
            ULONG State;
            ULONG WaitReason;
            ULONG SuspendCount;
            ULONG ContextSwitches;

            LARGE_INTEGER CreateTime;
            LARGE_INTEGER ExitTime;
            LARGE_INTEGER KernelTime;
            LARGE_INTEGER UserTime;
        } THREAD_EXTENDED_INFO, *PTHREAD_EXTENDED_INFO;

        //
        // -------------------------------------------------------------
        // QueryProcessExtended: 타겟 프로세스의 상세 메트릭 전수 조회
        // -------------------------------------------------------------
        //
        inline NTSTATUS QueryProcessExtended(
            _In_ HANDLE target_process_id,
            _Out_ PPROCESS_EXTENDED_INFO out_info
        )
        {
            if (out_info == nullptr)
                return STATUS_INVALID_PARAMETER;

            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            RtlZeroMemory(out_info, sizeof(*out_info));
            out_info->ProcessId = reinterpret_cast<ULONGLONG>(target_process_id);

            PEPROCESS process = nullptr;
            NTSTATUS status = PsLookupProcessByProcessId(target_process_id, &process);
            if (!NT_SUCCESS(status))
                return status;

            out_info->IsProtectedProcess = PsIsProtectedProcess(process) ? 1 : 0;
#ifdef _WIN64
            out_info->IsWow64 = (PsGetProcessWow64Process(process) != nullptr) ? 1 : 0;
#else
            out_info->IsWow64 = 0;
#endif

            PUNICODE_STRING proc_image_name = nullptr;
            if (NT_SUCCESS(SeLocateProcessImageName(process, &proc_image_name)) && proc_image_name != nullptr)
            {
                if (proc_image_name->Buffer != nullptr && proc_image_name->Length > 0)
                {
                    ULONG chars = proc_image_name->Length / sizeof(WCHAR);
                    if (chars > 259) chars = 259;
                    RtlCopyMemory(out_info->ImageFileName, proc_image_name->Buffer, chars * sizeof(WCHAR));
                    out_info->ImageFileName[chars] = L'\0';
                }
                ExFreePool(proc_image_name);
            }

            HANDLE process_handle = nullptr;
            status = ObOpenObjectByPointer(
                process,
                OBJ_KERNEL_HANDLE,
                nullptr,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                *PsProcessType,
                KernelMode,
                &process_handle
            );

            if (NT_SUCCESS(status))
            {
                ULONG ret_len = 0;

                PROCESS_BASIC_INFORMATION basic_info = {};
                if (NT_SUCCESS(ZwQueryInformationProcess(process_handle, ProcessBasicInformation, &basic_info, sizeof(basic_info), &ret_len)))
                {
                    out_info->ExitStatus = basic_info.ExitStatus;
                    out_info->PebBaseAddress = reinterpret_cast<ULONGLONG>(basic_info.PebBaseAddress);
                    out_info->AffinityMask = static_cast<ULONGLONG>(basic_info.AffinityMask);
                    out_info->BasePriority = basic_info.BasePriority;
                    out_info->ParentProcessId = static_cast<ULONGLONG>(basic_info.InheritedFromUniqueProcessId);
                }

                KERNEL_USER_TIMES times = {};
                if (NT_SUCCESS(ZwQueryInformationProcess(process_handle, ProcessTimes, &times, sizeof(times), &ret_len)))
                {
                    out_info->CreateTime = times.CreateTime;
                    out_info->ExitTime = times.ExitTime;
                    out_info->KernelTime = times.KernelTime;
                    out_info->UserTime = times.UserTime;
                }

                VM_COUNTERS_EX vm_counters = {};
                if (NT_SUCCESS(ZwQueryInformationProcess(process_handle, ProcessVmCounters, &vm_counters, sizeof(vm_counters), &ret_len)))
                {
                    out_info->PeakVirtualSize = vm_counters.PeakVirtualSize;
                    out_info->VirtualSize = vm_counters.VirtualSize;
                    out_info->PageFaultCount = vm_counters.PageFaultCount;
                    out_info->PeakWorkingSetSize = vm_counters.PeakWorkingSetSize;
                    out_info->WorkingSetSize = vm_counters.WorkingSetSize;
                    out_info->QuotaPagedPoolUsage = vm_counters.QuotaPagedPoolUsage;
                    out_info->QuotaNonPagedPoolUsage = vm_counters.QuotaNonPagedPoolUsage;
                    out_info->PagefileUsage = vm_counters.PagefileUsage;
                    out_info->PeakPagefileUsage = vm_counters.PeakPagefileUsage;
                    out_info->PrivateUsage = vm_counters.PrivateUsage;
                }

                ULONG handle_count = 0;
                if (NT_SUCCESS(ZwQueryInformationProcess(process_handle, ProcessHandleCount, &handle_count, sizeof(handle_count), &ret_len)))
                {
                    out_info->HandleCount = handle_count;
                }

                if (out_info->ImageFileName[0] == L'\0')
                {
                    UCHAR img_buf[512] = {};
                    if (NT_SUCCESS(ZwQueryInformationProcess(process_handle, ProcessImageFileName, img_buf, sizeof(img_buf), &ret_len)))
                    {
                        auto ustr = reinterpret_cast<PUNICODE_STRING>(img_buf);
                        if (ustr->Buffer != nullptr && ustr->Length > 0)
                        {
                            ULONG chars = ustr->Length / sizeof(WCHAR);
                            if (chars > 259) chars = 259;
                            if (reinterpret_cast<PUCHAR>(ustr->Buffer) >= img_buf &&
                                reinterpret_cast<PUCHAR>(ustr->Buffer) < img_buf + sizeof(img_buf))
                            {
                                RtlCopyMemory(out_info->ImageFileName, ustr->Buffer, chars * sizeof(WCHAR));
                            }
                            else
                            {
                                SIZE_T copied = 0;
                                MmCopyVirtualMemory(process, ustr->Buffer, PsGetCurrentProcess(), out_info->ImageFileName, chars * sizeof(WCHAR), KernelMode, &copied);
                            }
                            out_info->ImageFileName[chars] = L'\0';
                        }
                    }
                }

                UCHAR cmd_buf[1024] = {};
                if (NT_SUCCESS(ZwQueryInformationProcess(process_handle, ProcessCommandLineInformation, cmd_buf, sizeof(cmd_buf), &ret_len)))
                {
                    auto ustr = reinterpret_cast<PUNICODE_STRING>(cmd_buf);
                    if (ustr->Buffer != nullptr && ustr->Length > 0)
                    {
                        ULONG chars = ustr->Length / sizeof(WCHAR);
                        if (chars > 511) chars = 511;
                        if (reinterpret_cast<PUCHAR>(ustr->Buffer) >= cmd_buf &&
                            reinterpret_cast<PUCHAR>(ustr->Buffer) < cmd_buf + sizeof(cmd_buf))
                        {
                            RtlCopyMemory(out_info->CommandLine, ustr->Buffer, chars * sizeof(WCHAR));
                        }
                        else
                        {
                            SIZE_T copied = 0;
                            MmCopyVirtualMemory(process, ustr->Buffer, PsGetCurrentProcess(), out_info->CommandLine, chars * sizeof(WCHAR), KernelMode, &copied);
                        }
                        out_info->CommandLine[chars] = L'\0';
                    }
                }

                if (out_info->CommandLine[0] == L'\0' && out_info->PebBaseAddress != 0)
                {
                    PPEB peb = reinterpret_cast<PPEB>(out_info->PebBaseAddress);
                    PVOID proc_params = nullptr;
                    SIZE_T copied = 0;
                    if (NT_SUCCESS(MmCopyVirtualMemory(process, &peb->ProcessParameters, PsGetCurrentProcess(), &proc_params, sizeof(PVOID), KernelMode, &copied)) && proc_params != nullptr)
                    {
#ifdef _WIN64
                        ULONG_PTR cmd_offset = 0x70;
#else
                        ULONG_PTR cmd_offset = 0x40;
#endif
                        UNICODE_STRING target_cmd = {};
                        if (NT_SUCCESS(MmCopyVirtualMemory(process, reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(proc_params) + cmd_offset), PsGetCurrentProcess(), &target_cmd, sizeof(UNICODE_STRING), KernelMode, &copied)))
                        {
                            if (target_cmd.Buffer != nullptr && target_cmd.Length > 0)
                            {
                                ULONG copy_len = target_cmd.Length;
                                if (copy_len > 510 * sizeof(WCHAR)) copy_len = 510 * sizeof(WCHAR);
                                if (NT_SUCCESS(MmCopyVirtualMemory(process, target_cmd.Buffer, PsGetCurrentProcess(), out_info->CommandLine, copy_len, KernelMode, &copied)))
                                {
                                    out_info->CommandLine[copied / sizeof(WCHAR)] = L'\0';
                                }
                            }
                        }
                    }
                }

                if (out_info->PebBaseAddress != 0)
                {
                    PPEB peb = reinterpret_cast<PPEB>(out_info->PebBaseAddress);
                    UINT32 sess_id = 0;
                    SIZE_T copied = 0;
                    if (NT_SUCCESS(MmCopyVirtualMemory(process, &peb->SessionId, PsGetCurrentProcess(), &sess_id, sizeof(UINT32), KernelMode, &copied)))
                    {
                        out_info->SessionId = sess_id;
                    }
                }

                ZwClose(process_handle);
            }

            {
                ULONG size = 0x10000;
                ULONG returned = 0;
                PVOID buffer = nullptr;
                for (ULONG retry = 0; retry < 5; ++retry)
                {
                    buffer = helper::allocate::kernelmode::AllocateKernelMemory(size);
                    if (buffer == nullptr) break;

                    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, size, &returned);
                    if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
                        break;

                    helper::allocate::kernelmode::FreeKernelMemory(buffer);
                    buffer = nullptr;
                    size = (returned > size) ? (returned + 0x2000) : (size * 2);
                }

                if (buffer != nullptr)
                {
                    if (NT_SUCCESS(status))
                    {
                        const SIZE_T bytes = (returned && returned <= size) ? returned : size;
                        SIZE_T offset = 0;

                        while (offset < bytes)
                        {
                            auto pinfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(static_cast<PUCHAR>(buffer) + offset);
                            if (pinfo->UniqueProcessId == target_process_id)
                            {
                                out_info->ThreadCount = pinfo->NumberOfThreads;
                                break;
                            }

                            if (!pinfo->NextEntryOffset) break;
                            offset += pinfo->NextEntryOffset;
                        }
                    }
                    helper::allocate::kernelmode::FreeKernelMemory(buffer);
                }
            }

            ObDereferenceObject(process);
            return STATUS_SUCCESS;
        }

        //
        // -------------------------------------------------------------
        // QueryProcessHandles: 타겟 프로세스의 모든 핸들 전수 열거
        // -------------------------------------------------------------
        //
        inline NTSTATUS QueryProcessHandles(
            _In_ HANDLE target_process_id,
            _Out_writes_to_(max_handles, *returned_count) PPROCESS_HANDLE_ENTRY out_handles,
            _In_ ULONG max_handles,
            _Out_ PULONG returned_count
        )
        {
            if (out_handles == nullptr || max_handles == 0 || returned_count == nullptr)
                return STATUS_INVALID_PARAMETER;

            *returned_count = 0;

            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            ULONG size = 0x40000;
            ULONG returned = 0;
            PVOID buffer = nullptr;
            NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

            for (ULONG retry = 0; retry < 10; ++retry)
            {
                buffer = helper::allocate::kernelmode::AllocateKernelMemory(size);
                if (buffer == nullptr)
                    return STATUS_INSUFFICIENT_RESOURCES;

                status = ZwQuerySystemInformation(SystemExtendedHandleInformation, buffer, size, &returned);
                if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
                    break;

                helper::allocate::kernelmode::FreeKernelMemory(buffer);
                buffer = nullptr;
                size = (returned > size) ? (returned + 0x10000) : (size * 2);
            }

            if (!NT_SUCCESS(status) || buffer == nullptr)
            {
                if (buffer != nullptr)
                    helper::allocate::kernelmode::FreeKernelMemory(buffer);
                return status;
            }

            auto handle_info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer);
            ULONG count = 0;
            ULONG_PTR target_pid = reinterpret_cast<ULONG_PTR>(target_process_id);

            for (ULONG_PTR i = 0; i < handle_info->NumberOfHandles && count < max_handles; ++i)
            {
                if (handle_info->Handles[i].UniqueProcessId == target_pid)
                {
                    out_handles[count].HandleValue = handle_info->Handles[i].HandleValue;
                    out_handles[count].ObjectTypeIndex = static_cast<ULONG>(handle_info->Handles[i].ObjectTypeIndex);
                    out_handles[count].GrantedAccess = handle_info->Handles[i].GrantedAccess;
                    out_handles[count].ObjectPointer = reinterpret_cast<ULONGLONG>(handle_info->Handles[i].Object);
                    count++;
                }
            }

            helper::allocate::kernelmode::FreeKernelMemory(buffer);
            *returned_count = count;
            return STATUS_SUCCESS;
        }

        //
        // -------------------------------------------------------------
        // QueryProcessToken: 타겟 프로세스의 보안 토큰/권한/무결성 수준 조회
        // -------------------------------------------------------------
        //
        inline NTSTATUS QueryProcessToken(
            _In_ HANDLE target_process_id,
            _Out_ PPROCESS_TOKEN_INFO out_info
        )
        {
            if (out_info == nullptr)
                return STATUS_INVALID_PARAMETER;

            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            RtlZeroMemory(out_info, sizeof(*out_info));
            out_info->ProcessId = reinterpret_cast<ULONGLONG>(target_process_id);

            PEPROCESS process = nullptr;
            NTSTATUS status = PsLookupProcessByProcessId(target_process_id, &process);
            if (!NT_SUCCESS(status))
                return status;

            HANDLE proc_handle = nullptr;
            status = ObOpenObjectByPointer(
                process,
                OBJ_KERNEL_HANDLE,
                nullptr,
                PROCESS_QUERY_INFORMATION,
                *PsProcessType,
                KernelMode,
                &proc_handle
            );

            if (NT_SUCCESS(status))
            {
                HANDLE token_handle = nullptr;
                status = ZwOpenProcessTokenEx(
                    proc_handle,
                    TOKEN_QUERY,
                    OBJ_KERNEL_HANDLE,
                    &token_handle
                );

                if (NT_SUCCESS(status))
                {
                    ULONG ret_len = 0;

                    TOKEN_ELEVATION elevation = {};
                    if (NT_SUCCESS(ZwQueryInformationToken(token_handle, TokenElevation, &elevation, sizeof(elevation), &ret_len)))
                    {
                        out_info->IsElevated = elevation.TokenIsElevated;
                    }

                    TOKEN_ELEVATION_TYPE elev_type = TokenElevationTypeDefault;
                    if (NT_SUCCESS(ZwQueryInformationToken(token_handle, TokenElevationType, &elev_type, sizeof(elev_type), &ret_len)))
                    {
                        out_info->ElevationType = static_cast<ULONG>(elev_type);
                    }

                    UCHAR il_buffer[sizeof(TOKEN_MANDATORY_LABEL) + 64] = {};
                    if (NT_SUCCESS(ZwQueryInformationToken(token_handle, TokenIntegrityLevel, il_buffer, sizeof(il_buffer), &ret_len)))
                    {
                        auto pml = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(il_buffer);
                        if (pml->Label.Sid != nullptr)
                        {
                            PUCHAR sub_auth_count = RtlSubAuthorityCountSid(pml->Label.Sid);
                            if (sub_auth_count != nullptr && *sub_auth_count > 0)
                            {
                                PULONG rid = RtlSubAuthoritySid(pml->Label.Sid, static_cast<ULONG>(*sub_auth_count - 1));
                                if (rid != nullptr)
                                {
                                    out_info->IntegrityLevel = *rid;
                                }
                            }
                        }
                    }

                    ULONG session_id = 0;
                    if (NT_SUCCESS(ZwQueryInformationToken(token_handle, TokenSessionId, &session_id, sizeof(session_id), &ret_len)))
                    {
                        out_info->SessionId = session_id;
                    }

                    UCHAR priv_buf[1024] = {};
                    if (NT_SUCCESS(ZwQueryInformationToken(token_handle, TokenPrivileges, priv_buf, sizeof(priv_buf), &ret_len)))
                    {
                        auto privs = reinterpret_cast<PTOKEN_PRIVILEGES>(priv_buf);
                        out_info->PrivilegeCount = privs->PrivilegeCount;
                        for (ULONG i = 0; i < privs->PrivilegeCount; ++i)
                        {
                            if (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                            {
                                ULONG luid_low = privs->Privileges[i].Luid.LowPart;
                                if (luid_low < 64)
                                {
                                    out_info->EnabledPrivilegesMask |= (1ULL << luid_low);
                                }
                            }
                        }
                    }

                    ZwClose(token_handle);
                    status = STATUS_SUCCESS;
                }

                ZwClose(proc_handle);
            }

            ObDereferenceObject(process);
            return status;
        }

        //
        // -------------------------------------------------------------
        // QueryThreadExtended: TEB, Win32 진입점, 스레드 시간, 상세 상태 조회
        // -------------------------------------------------------------
        //
        inline NTSTATUS QueryThreadExtended(
            _In_ HANDLE thread_id,
            _Out_ PTHREAD_EXTENDED_INFO out_info
        )
        {
            if (out_info == nullptr)
                return STATUS_INVALID_PARAMETER;

            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            RtlZeroMemory(out_info, sizeof(*out_info));
            out_info->ThreadId = reinterpret_cast<ULONGLONG>(thread_id);

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            HANDLE thread_handle = nullptr;
            status = ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                *PsThreadType,
                KernelMode,
                &thread_handle
            );

            if (NT_SUCCESS(status))
            {
                ULONG ret_len = 0;

                THREAD_BASIC_INFORMATION basic_info = {};
                if (NT_SUCCESS(ZwQueryInformationThread(thread_handle, ThreadBasicInformation, &basic_info, sizeof(basic_info), &ret_len)))
                {
                    out_info->ExitStatus = basic_info.ExitStatus;
                    out_info->TebBaseAddress = reinterpret_cast<ULONGLONG>(basic_info.TebBaseAddress);
                    out_info->ProcessId = reinterpret_cast<ULONGLONG>(basic_info.ClientId.UniqueProcess);
                    out_info->AffinityMask = static_cast<ULONGLONG>(basic_info.AffinityMask);
                    out_info->Priority = basic_info.Priority;
                    out_info->BasePriority = basic_info.BasePriority;
                }

                PVOID win32_start = nullptr;
            if (NT_SUCCESS(ZwQueryInformationThread(thread_handle, ThreadQuerySetWin32StartAddress, &win32_start, sizeof(PVOID), &ret_len)))
                {
                    out_info->Win32StartAddress = reinterpret_cast<ULONGLONG>(win32_start);
                }

                KERNEL_USER_TIMES times = {};
                if (NT_SUCCESS(ZwQueryInformationThread(thread_handle, ThreadTimes, &times, sizeof(times), &ret_len)))
                {
                    out_info->CreateTime = times.CreateTime;
                    out_info->ExitTime = times.ExitTime;
                    out_info->KernelTime = times.KernelTime;
                    out_info->UserTime = times.UserTime;
                }

                ULONG suspend_count = 0;
                if (NT_SUCCESS(ZwQueryInformationThread(thread_handle, ThreadSuspendCount, &suspend_count, sizeof(suspend_count), &ret_len)))
                {
                    out_info->SuspendCount = suspend_count;
                }

                ZwClose(thread_handle);
            }

            if (out_info->ProcessId != 0)
            {
                ULONG size = 0x10000;
                ULONG returned = 0;
                PVOID buffer = nullptr;
                for (ULONG retry = 0; retry < 5; ++retry)
                {
                    buffer = helper::allocate::kernelmode::AllocateKernelMemory(size);
                    if (buffer == nullptr) break;

                    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, size, &returned);
                    if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
                        break;

                    helper::allocate::kernelmode::FreeKernelMemory(buffer);
                    buffer = nullptr;
                    size = (returned > size) ? (returned + 0x2000) : (size * 2);
                }

                if (buffer != nullptr)
                {
                    if (NT_SUCCESS(status))
                    {
                        const SIZE_T bytes = (returned && returned <= size) ? returned : size;
                        SIZE_T offset = 0;
                        BOOLEAN found = FALSE;

                        while (offset < bytes)
                        {
                            auto pinfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(static_cast<PUCHAR>(buffer) + offset);
                            if (reinterpret_cast<ULONGLONG>(pinfo->UniqueProcessId) == out_info->ProcessId)
                            {
                                for (ULONG i = 0; i < pinfo->NumberOfThreads; ++i)
                                {
                                    if (reinterpret_cast<ULONGLONG>(pinfo->Threads[i].ClientId.UniqueThread) == out_info->ThreadId)
                                    {
                                        out_info->StartAddress = reinterpret_cast<ULONGLONG>(pinfo->Threads[i].StartAddress);
                                        out_info->State = pinfo->Threads[i].ThreadState;
                                        out_info->WaitReason = pinfo->Threads[i].WaitReason;
                                        out_info->ContextSwitches = pinfo->Threads[i].ContextSwitches;
                                        found = TRUE;
                                        break;
                                    }
                                }
                                if (found) break;
                            }

                            if (!pinfo->NextEntryOffset) break;
                            offset += pinfo->NextEntryOffset;
                        }
                    }
                    helper::allocate::kernelmode::FreeKernelMemory(buffer);
                }
            }

            ObDereferenceObject(thread);
            return STATUS_SUCCESS;
        }

        //
        // -------------------------------------------------------------
        // SetThreadPriority: 스레드 우선순위 변경
        // -------------------------------------------------------------
        //
        inline NTSTATUS SetThreadPriority(
            _In_ HANDLE thread_id,
            _In_ LONG priority
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            HANDLE thread_handle = nullptr;
            status = ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_SET_INFORMATION,
                *PsThreadType,
                KernelMode,
                &thread_handle
            );

            if (NT_SUCCESS(status))
            {
                status = ZwSetInformationThread(
                    thread_handle,
                    ThreadPriority,
                    &priority,
                    sizeof(LONG)
                );
                ZwClose(thread_handle);
            }

            ObDereferenceObject(thread);
            return status;
        }

        //
        // -------------------------------------------------------------
        // SetThreadAffinity: 스레드 친화도 (CPU 코어 바인딩) 설정
        // -------------------------------------------------------------
        //
        inline NTSTATUS SetThreadAffinity(
            _In_ HANDLE thread_id,
            _In_ ULONGLONG affinity_mask
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            HANDLE thread_handle = nullptr;
            status = ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_SET_INFORMATION,
                *PsThreadType,
                KernelMode,
                &thread_handle
            );

            if (NT_SUCCESS(status))
            {
                KAFFINITY k_affinity = static_cast<KAFFINITY>(affinity_mask);
                status = ZwSetInformationThread(
                    thread_handle,
                    ThreadAffinityMask,
                    &k_affinity,
                    sizeof(KAFFINITY)
                );
                ZwClose(thread_handle);
            }

            ObDereferenceObject(thread);
            return status;
        }

        //
        // -------------------------------------------------------------
        // TerminateThread: 특정 타겟 스레드 안전 강제 종료
        // -------------------------------------------------------------
        //
        inline NTSTATUS TerminateThread(
            _In_ HANDLE thread_id,
            _In_ NTSTATUS exit_status
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            //
            // 1. ObOpenObjectByPointer를 통해 커널 스레드 핸들 획득 (THREAD_TERMINATE 권한)
            //
            HANDLE thread_handle = nullptr;
            status = ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_TERMINATE,
                *PsThreadType,
                KernelMode,
                &thread_handle
            );

            if (NT_SUCCESS(status))
            {
                //
                // 2. 표준 커널 루틴 ZwTerminateThread를 호출하여 안전하게 종료
                //
                UNICODE_STRING routine_name = RTL_CONSTANT_STRING(L"ZwTerminateThread");
                using TERMINATE_THREAD = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
                auto terminate = reinterpret_cast<TERMINATE_THREAD>(MmGetSystemRoutineAddress(&routine_name));
                status = terminate ? terminate(thread_handle, exit_status) : STATUS_PROCEDURE_NOT_FOUND;
                ZwClose(thread_handle);
            }
            else
            {
                //
                // 3. Fallback: 컨텍스트 리다이렉션을 통한 유저 모드 종료 유도
                //
                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (NT_SUCCESS(TransferThreadContext(thread, &ctx, FALSE)))
                {
                    ctx.Rip = 0;
                    status = TransferThreadContext(thread, &ctx, TRUE);
                }
            }

            ObDereferenceObject(thread);
            return status;
        }

        //
        // -------------------------------------------------------------
        // SetThreadHideFromDebugger: 디버거로부터 스레드 숨김 설정
        // -------------------------------------------------------------
        //
        inline NTSTATUS SetThreadHideFromDebugger(
            _In_ HANDLE thread_id
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            PETHREAD thread = nullptr;
            NTSTATUS status = PsLookupThreadByThreadId(thread_id, &thread);
            if (!NT_SUCCESS(status))
                return status;

            HANDLE thread_handle = nullptr;
            status = ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_SET_INFORMATION,
                *PsThreadType,
                KernelMode,
                &thread_handle
            );

            if (NT_SUCCESS(status))
            {
                status = ZwSetInformationThread(
                    thread_handle,
                    ThreadHideFromDebugger,
                    nullptr,
                    0
                );
                ZwClose(thread_handle);
            }

            ObDereferenceObject(thread);
            return status;
        }
    }
    
    namespace Copy
    {
        namespace usermode
        {
            inline NTSTATUS CopyProcessMemory(
                _In_ HANDLE source_process_handle,
                _In_ PVOID source_address,
                _In_ HANDLE destination_process_handle,
                _In_ PVOID destination_address,
                _In_ SIZE_T size,
                _Out_opt_ PSIZE_T copied_size
            )
            {
                // ObReferenceObjectByHandle below requires PASSIVE_LEVEL.
                if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                    return STATUS_INVALID_DEVICE_STATE;

                if (
                    source_process_handle == nullptr ||
                    destination_process_handle == nullptr ||
                    source_address == nullptr ||
                    destination_address == nullptr ||
                    size == 0
                    )
                {
                    return STATUS_INVALID_PARAMETER;
                }

                SIZE_T local_copied_size = 0;

                if (copied_size == nullptr)
                    copied_size = &local_copied_size;

                *copied_size = 0;


                PEPROCESS source_process = nullptr;
                PEPROCESS destination_process = nullptr;


                //
                // Source HANDLE -> referenced EPROCESS
                //
                NTSTATUS status = ObReferenceObjectByHandle(
                    source_process_handle,
                    PROCESS_VM_READ,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(&source_process),
                    nullptr
                );

                if (!NT_SUCCESS(status))
                    return status;


                //
                // Destination HANDLE -> referenced EPROCESS
                //
                status = ObReferenceObjectByHandle(
                    destination_process_handle,
                    PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(&destination_process),
                    nullptr
                );

                if (!NT_SUCCESS(status))
                {
                    ObDereferenceObject(
                        source_process
                    );

                    return status;
                }


                //
                // Source Process VA
                //          ↓
                // Destination Process VA
                //
                status = MmCopyVirtualMemory(
                    source_process,
                    source_address,

                    destination_process,
                    destination_address,

                    size,

                    KernelMode,

                    copied_size
                );


                //
                // Release both EPROCESS references.
                //
                ObDereferenceObject(
                    destination_process
                );

                ObDereferenceObject(
                    source_process
                );


                return status;
            }

            inline NTSTATUS WriteProcessMemory(
                _In_ HANDLE target_process_handle,
                _In_ PVOID target_address,
                _In_ PVOID source_buffer,
                _In_ SIZE_T size,
                _Out_opt_ PSIZE_T bytes_written
            )
            {
                // ObReferenceObjectByHandle below requires PASSIVE_LEVEL.
                if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                    return STATUS_INVALID_DEVICE_STATE;

                if (
                    target_process_handle == nullptr ||
                    target_address == nullptr ||
                    source_buffer == nullptr ||
                    size == 0
                    )
                {
                    return STATUS_INVALID_PARAMETER;
                }

                SIZE_T local_written = 0;
                if (bytes_written == nullptr)
                    bytes_written = &local_written;
                *bytes_written = 0;

                PEPROCESS target_process = nullptr;
                NTSTATUS status = ObReferenceObjectByHandle(
                    target_process_handle,
                    PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(&target_process),
                    nullptr
                );

                if (!NT_SUCCESS(status))
                    return status;

                status = MmCopyVirtualMemory(
                    PsGetCurrentProcess(),
                    source_buffer,
                    target_process,
                    target_address,
                    size,
                    KernelMode,
                    bytes_written
                );

                ObDereferenceObject(target_process);
                return status;
            }
        }
    }

    namespace scan
    {
        namespace process
        {
            constexpr SIZE_T PROCESS_SCAN_CHUNK_SIZE =
                0x10000; // 64 KB


            inline PVOID ScanValueProcess(
                _In_ HANDLE source_process_handle,
                _In_ PVOID source_value,
                _In_ ULONGLONG source_value_size,
                _In_ ULONG page_protect,
                _In_ HANDLE target_process_handle,
                _Out_opt_ NTSTATUS* result_status = nullptr
            )
            {
                if (result_status) *result_status = STATUS_UNSUCCESSFUL;
                ULONG result_count = 0;
                NTSTATUS scan_status = STATUS_SUCCESS;
                //
                // This scanner is PASSIVE_LEVEL only.
                //
                if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                    return nullptr;


                if (
                    source_process_handle == nullptr ||
                    source_value == nullptr ||
                    source_value_size == 0 ||
                    target_process_handle == nullptr
                    )
                {
                    return nullptr;
                }


                if (
                    source_value_size >
                    static_cast<ULONGLONG>(MAXSIZE_T)
                    )
                {
                    return nullptr;
                }


                SIZE_T pattern_size =
                    static_cast<SIZE_T>(
                        source_value_size
                        );


                //
                // ---------------------------------------------------------
                // Obtain Source EPROCESS.
                //
                // Used when SourceValue is a User VA.
                // ---------------------------------------------------------
                //

                PEPROCESS source_process = nullptr;

                NTSTATUS status =
                    ObReferenceObjectByHandle(
                        source_process_handle,
                        PROCESS_VM_READ,
                        *PsProcessType,
                        KernelMode,
                        reinterpret_cast<PVOID*>(
                            &source_process
                            ),
                        nullptr
                    );

                if (!NT_SUCCESS(status))
                    return nullptr;


                //
                // ---------------------------------------------------------
                // Obtain Target EPROCESS.
                //
                // Needed for short KeStackAttachProcess() operations
                // while copying target process memory.
                // ---------------------------------------------------------
                //

                PEPROCESS target_process = nullptr;

                status =
                    ObReferenceObjectByHandle(
                        target_process_handle,
                        PROCESS_QUERY_INFORMATION |
                        PROCESS_VM_READ,
                        *PsProcessType,
                        KernelMode,
                        reinterpret_cast<PVOID*>(
                            &target_process
                            ),
                        nullptr
                    );

                if (!NT_SUCCESS(status))
                {
                    ObDereferenceObject(
                        source_process
                    );

                    return nullptr;
                }


                //
                // ---------------------------------------------------------
                // Allocate kernel snapshot for SourceValue.
                //
                // SourceValue itself may later change, so the entire scan
                // compares against one fixed pattern.
                // ---------------------------------------------------------
                //

                PUCHAR pattern_buffer =
                    static_cast<PUCHAR>(
                        helper::allocate::kernelmode::
                        AllocateKernelMemory(
                            pattern_size
                        )
                        );

                if (pattern_buffer == nullptr)
                {
                    ObDereferenceObject(
                        target_process
                    );

                    ObDereferenceObject(
                        source_process
                    );

                    return nullptr;
                }


                BOOLEAN pattern_copy_success =
                    FALSE;


                //
                // ---------------------------------------------------------
                // SourceValue can be either:
                //
                //   1. Source Process User VA
                //   2. Kernel VA
                // ---------------------------------------------------------
                //

                if (
                    reinterpret_cast<ULONG_PTR>(
                        source_value
                        ) <=
                    reinterpret_cast<ULONG_PTR>(
                        MmHighestUserAddress
                        )
                    )
                {
                    //
                    // SourceValue = SourceProcess User VA
                    //

                    KAPC_STATE apc_state = {};

                    KeStackAttachProcess(
                        source_process,
                        &apc_state
                    );

                    __try
                    {
                        ProbeForRead(
                            source_value,
                            pattern_size,
                            sizeof(UCHAR)
                        );

                        RtlCopyMemory(
                            pattern_buffer,
                            source_value,
                            pattern_size
                        );

                        pattern_copy_success =
                            TRUE;
                    }
                    __except (
                        EXCEPTION_EXECUTE_HANDLER
                        )
                    {
                        pattern_copy_success =
                            FALSE;
                    }

                    KeUnstackDetachProcess(
                        &apc_state
                    );
                }
                else
                {
                    //
                    // SourceValue = Kernel VA
                    //

                    __try
                    {
                        RtlCopyMemory(
                            pattern_buffer,
                            source_value,
                            pattern_size
                        );

                        pattern_copy_success =
                            TRUE;
                    }
                    __except (
                        EXCEPTION_EXECUTE_HANDLER
                        )
                    {
                        pattern_copy_success =
                            FALSE;
                    }
                }


                if (!pattern_copy_success)
                {
                    helper::allocate::kernelmode::
                        FreeKernelMemory(
                            pattern_buffer
                        );

                    ObDereferenceObject(
                        target_process
                    );

                    ObDereferenceObject(
                        source_process
                    );

                    return nullptr;
                }


                //
                // ---------------------------------------------------------
                // Kernel scan buffer.
                //
                // Extra pattern_size bytes are used so that pattern
                // matches crossing a 64 KB chunk boundary are preserved.
                // ---------------------------------------------------------
                //

                SIZE_T scan_buffer_size =
                    PROCESS_SCAN_CHUNK_SIZE;

                if (
                    pattern_size >
                    MAXSIZE_T - scan_buffer_size
                    )
                {
                    helper::allocate::kernelmode::
                        FreeKernelMemory(
                            pattern_buffer
                        );

                    ObDereferenceObject(
                        target_process
                    );

                    ObDereferenceObject(
                        source_process
                    );

                    return nullptr;
                }


                scan_buffer_size +=
                    pattern_size;


                PUCHAR scan_buffer =
                    static_cast<PUCHAR>(
                        helper::allocate::kernelmode::
                        AllocateKernelMemory(
                            scan_buffer_size
                        )
                        );

                if (scan_buffer == nullptr)
                {
                    helper::allocate::kernelmode::
                        FreeKernelMemory(
                            pattern_buffer
                        );

                    ObDereferenceObject(
                        target_process
                    );

                    ObDereferenceObject(
                        source_process
                    );

                    return nullptr;
                }


                //
                // Result linked-list.
                //
                // Both addresses are SourceProcess User Virtual Addresses.
                //

                PVOID first_node_address =
                    nullptr;

                PVOID latest_node_address =
                    nullptr;


                //
                // Start scanning from the lowest User VA.
                //

                PVOID query_address =
                    nullptr;


                for (;;)
                {
                    MEMORY_BASIC_INFORMATION mbi = {};

                    SIZE_T return_length = 0;


                    status =
                        ZwQueryVirtualMemory(
                            target_process_handle,
                            query_address,
                            MemoryBasicInformation,
                            &mbi,
                            sizeof(mbi),
                            &return_length
                        );


                    if (!NT_SUCCESS(status))
                        break;


                    ULONG_PTR region_base =
                        reinterpret_cast<ULONG_PTR>(
                            mbi.BaseAddress
                            );

                    ULONG_PTR highest_user =
                        reinterpret_cast<ULONG_PTR>(
                            MmHighestUserAddress
                            );


                    if (region_base > highest_user)
                        break;


                    //
                    // Calculate next region before doing anything else.
                    //

                    if (
                        mbi.RegionSize == 0 ||
                        region_base >
                        MAXULONG_PTR - mbi.RegionSize
                        )
                    {
                        break;
                    }


                    ULONG_PTR next_region =
                        region_base +
                        mbi.RegionSize;


                    //
                    // -----------------------------------------------------
                    // Scan only:
                    //
                    //  * committed memory
                    //  * exact PAGE protection requested by caller
                    //
                    // Guard pages are deliberately skipped because reading
                    // them changes guard-page state / raises an exception.
                    // -----------------------------------------------------
                    //

                    BOOLEAN eligible_region =
                        (
                            mbi.State == MEM_COMMIT &&
                            mbi.Protect == page_protect &&
                            (mbi.Protect & PAGE_GUARD) == 0 &&
                            (mbi.Protect & PAGE_NOACCESS) == 0
                            );


                    if (
                        eligible_region &&
                        mbi.RegionSize >= pattern_size
                        )
                    {
                        SIZE_T region_offset = 0;


                        while (
                            region_offset <
                            mbi.RegionSize
                            )
                        {
                            SIZE_T remaining =
                                mbi.RegionSize -
                                region_offset;


                            //
                            // Copy one chunk plus overlap.
                            //

                            SIZE_T copy_size =
                                PROCESS_SCAN_CHUNK_SIZE;


                            if (copy_size > remaining)
                                copy_size = remaining;


                            //
                            // Add overlap so a match crossing
                            // the chunk boundary isn't lost.
                            //

                            if (
                                remaining > copy_size &&
                                pattern_size > 1
                                )
                            {
                                SIZE_T overlap =
                                    pattern_size - 1;


                                if (
                                    overlap >
                                    remaining - copy_size
                                    )
                                {
                                    overlap =
                                        remaining -
                                        copy_size;
                                }


                                copy_size += overlap;
                            }


                            PVOID target_chunk_address =
                                reinterpret_cast<PVOID>(
                                    region_base +
                                    region_offset
                                    );


                            BOOLEAN copy_success =
                                FALSE;


                            //
                            // Attach only for the target memory copy.
                            // Actual memcmp scanning happens after detach.
                            //

                            KAPC_STATE apc_state = {};

                            KeStackAttachProcess(
                                target_process,
                                &apc_state
                            );


                            __try
                            {
                                ProbeForRead(
                                    target_chunk_address,
                                    copy_size,
                                    sizeof(UCHAR)
                                );


                                RtlCopyMemory(
                                    scan_buffer,
                                    target_chunk_address,
                                    copy_size
                                );


                                copy_success =
                                    TRUE;
                            }
                            __except (
                                EXCEPTION_EXECUTE_HANDLER
                                )
                            {
                                copy_success =
                                    FALSE;
                            }


                            KeUnstackDetachProcess(
                                &apc_state
                            );


                            if (copy_success)
                            {
                                if (
                                    copy_size >=
                                    pattern_size
                                    )
                                {
                                    SIZE_T maximum_offset =
                                        copy_size -
                                        pattern_size;


                                    //
                                    // Do not rescan overlap already
                                    // processed by previous chunk.
                                    //
                                    SIZE_T primary_scan_size =
                                        PROCESS_SCAN_CHUNK_SIZE;


                                    if (
                                        primary_scan_size >
                                        remaining
                                        )
                                    {
                                        primary_scan_size =
                                            remaining;
                                    }


                                    SIZE_T maximum_primary_offset;

                                    if (
                                        primary_scan_size >=
                                        pattern_size
                                        )
                                    {
                                        maximum_primary_offset =
                                            primary_scan_size - 1;
                                    }
                                    else
                                    {
                                        maximum_primary_offset =
                                            maximum_offset;
                                    }


                                    if (
                                        maximum_primary_offset >
                                        maximum_offset
                                        )
                                    {
                                        maximum_primary_offset =
                                            maximum_offset;
                                    }


                                    //
                                    // -------------------------------------------------
                                    // Byte-by-byte exact value scan.
                                    // -------------------------------------------------
                                    //

                                    for (
                                        SIZE_T offset = 0;
                                        offset <=
                                        maximum_primary_offset;
                                        ++offset
                                        )
                                    {
                                        if (
                                            RtlCompareMemory(
                                                scan_buffer +
                                                offset,
                                                pattern_buffer,
                                                pattern_size
                                            ) !=
                                            pattern_size
                                            )
                                        {
                                            continue;
                                        }


                                        //
                                        // Exact matched TargetProcess VA.
                                        //

                                        PVOID matched_address =
                                            reinterpret_cast<PVOID>(
                                                region_base +
                                                region_offset +
                                                offset
                                                );


                                        //
                                        // -------------------------------------------------
                                        // Store the matched ADDRESS as node Data.
                                        //
                                        // InsertList copies sizeof(PVOID) bytes
                                        // into SourceProcess User VA.
                                        // -------------------------------------------------
                                        //

                                        if (result_count >= helper::linkedlist::MAX_USER_RESULT_NODES)
                                        {
                                            scan_status = STATUS_QUOTA_EXCEEDED;
                                            goto ScanValueCleanup;
                                        }
                                        ++result_count;
                                        PVOID new_node =
                                            helper::linkedlist::
                                            usermode::InsertList(
                                                source_process_handle,
                                                latest_node_address,

                                                reinterpret_cast<PUCHAR>(
                                                    &matched_address
                                                    ),

                                    sizeof(PVOID)
                                            );


                                        if (new_node == nullptr)
                                        {
                                            //
                                            // Allocation/list failure:
                                            // release everything created so far.
                                            //

                                            if (
                                                first_node_address !=
                                                nullptr
                                                )
                                            {
                                                helper::linkedlist::
                                                    usermode::
                                                    FreeLinkedList(
                                                        source_process_handle,
                                                        first_node_address
                                                    );
                                            }


                                            helper::allocate::
                                                kernelmode::
                                                FreeKernelMemory(
                                                    scan_buffer
                                                );

                                            helper::allocate::
                                                kernelmode::
                                                FreeKernelMemory(
                                                    pattern_buffer
                                                );


                                            ObDereferenceObject(
                                                target_process
                                            );

                                            ObDereferenceObject(
                                                source_process
                                            );


                                            return nullptr;
                                        }


                                        latest_node_address =
                                            new_node;


                                        if (
                                            first_node_address ==
                                            nullptr
                                            )
                                        {
                                            first_node_address =
                                                new_node;
                                        }
                                    }
                                }
                            }


                            //
                            // Advance by primary chunk only.
                            // overlap belongs to the next iteration.
                            //

                            SIZE_T advance =
                                PROCESS_SCAN_CHUNK_SIZE;


                            if (advance > remaining)
                                advance = remaining;


                            region_offset +=
                                advance;
                        }
                    }


                    query_address =
                        reinterpret_cast<PVOID>(
                            next_region
                            );


                    if (next_region > highest_user)
                        break;
                }


                //
                // Cleanup temporary kernel resources.
                //

            ScanValueCleanup:
                if (!NT_SUCCESS(scan_status) && first_node_address)
                {
                    NTSTATUS release_status = helper::linkedlist::usermode::FreeLinkedList(
                        source_process_handle, first_node_address);
                    if (!NT_SUCCESS(release_status)) scan_status = release_status;
                    first_node_address = nullptr;
                }
                helper::allocate::kernelmode::
                    FreeKernelMemory(
                        scan_buffer
                    );

                helper::allocate::kernelmode::
                    FreeKernelMemory(
                        pattern_buffer
                    );


                ObDereferenceObject(
                    target_process
                );

                ObDereferenceObject(
                    source_process
                );


                //
                // nullptr:
                //   no matches
                //
                // non-null:
                //   SourceProcess User VA of the first result node.
                //
                if (result_status) *result_status = first_node_address ? STATUS_SUCCESS :
                    (NT_SUCCESS(scan_status) ? STATUS_NOT_FOUND : scan_status);
                return first_node_address;
            }

            inline BOOLEAN MatchMask(
                _In_ const UCHAR* data,
                _In_ const UCHAR* pattern,
                _In_opt_ const CHAR* mask,
                _In_ SIZE_T length
            )
            {
                BOOLEAN mask_ended = FALSE;
                for (SIZE_T i = 0; i < length; ++i)
                {
                    if (mask != nullptr && !mask_ended)
                    {
                        if (mask[i] == '\0')
                        {
                            mask_ended = TRUE;
                        }
                        else if (mask[i] == '?')
                        {
                            continue;
                        }
                    }
                    if (data[i] != pattern[i])
                        return FALSE;
                }
                return TRUE;
            }

            inline NTSTATUS ScanPatternProcess(
                _In_ HANDLE target_process_handle,
                _In_opt_ PVOID start_address,
                _In_opt_ SIZE_T scan_length,
                _In_ const UCHAR* pattern,
                _In_opt_ const CHAR* mask,
                _In_ SIZE_T pattern_length,
                _In_ ULONG page_protect,
                _Out_ PVOID* first_match_address,
                _Out_ PULONG matches_count
            )
            {
                if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                    return STATUS_INVALID_DEVICE_STATE;

                if (target_process_handle == nullptr || pattern == nullptr || pattern_length == 0 ||
                    first_match_address == nullptr || matches_count == nullptr)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                const ULONG_PTR requested_start = start_address
                    ? reinterpret_cast<ULONG_PTR>(start_address) : 0x10000;
                const ULONG_PTR highest_user = reinterpret_cast<ULONG_PTR>(MmHighestUserAddress);
                if (requested_start > highest_user ||
                    (scan_length && scan_length - 1 > highest_user - requested_start) ||
                    pattern_length > MAXSIZE_T - PROCESS_SCAN_CHUNK_SIZE)
                    return STATUS_INVALID_PARAMETER;

                *first_match_address = nullptr;
                *matches_count = 0;

                PEPROCESS target_process = nullptr;
                NTSTATUS status = ObReferenceObjectByHandle(
                    target_process_handle,
                    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(&target_process),
                    nullptr
                );

                if (!NT_SUCCESS(status))
                    return status;

                PUCHAR chunk_buffer = static_cast<PUCHAR>(
                    helper::allocate::kernelmode::AllocateKernelMemory(PROCESS_SCAN_CHUNK_SIZE + pattern_length)
                );
                if (chunk_buffer == nullptr)
                {
                    ObDereferenceObject(target_process);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                ULONG_PTR current_va = reinterpret_cast<ULONG_PTR>(start_address ? start_address : reinterpret_cast<PVOID>(0x10000));
                ULONG_PTR max_va = scan_length ? (current_va + scan_length) : reinterpret_cast<ULONG_PTR>(MmHighestUserAddress);
                if (max_va > reinterpret_cast<ULONG_PTR>(MmHighestUserAddress))
                    max_va = reinterpret_cast<ULONG_PTR>(MmHighestUserAddress);

                ULONG total_matches = 0;
                PVOID first_match = nullptr;

                while (current_va < max_va)
                {
                    MEMORY_BASIC_INFORMATION mbi = {};
                    SIZE_T return_len = 0;

                    status = ZwQueryVirtualMemory(
                        target_process_handle,
                        reinterpret_cast<PVOID>(current_va),
                        MemoryBasicInformation,
                        &mbi,
                        sizeof(mbi),
                        &return_len
                    );

                    if (!NT_SUCCESS(status) || mbi.RegionSize == 0)
                        break;

                    ULONG_PTR region_end = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
                    if (region_end > max_va)
                        region_end = max_va;

                    BOOLEAN can_scan = (mbi.State == MEM_COMMIT) &&
                                       !(mbi.Protect & PAGE_GUARD) &&
                                       !(mbi.Protect & PAGE_NOACCESS);

                    if (page_protect != 0)
                    {
                        if ((mbi.Protect & page_protect) == 0)
                            can_scan = FALSE;
                    }

                    if (can_scan && region_end > current_va)
                    {
                        ULONG_PTR scan_ptr = current_va;
                        while (scan_ptr < region_end)
                        {
                            SIZE_T to_read = (region_end - scan_ptr < PROCESS_SCAN_CHUNK_SIZE)
                                ? (region_end - scan_ptr)
                                : PROCESS_SCAN_CHUNK_SIZE;

                            const SIZE_T tail = region_end - scan_ptr - to_read;
                            const SIZE_T overlap = tail < pattern_length - 1 ? tail : pattern_length - 1;
                            SIZE_T read_with_overlap = to_read + overlap;

                            SIZE_T bytes_read = 0;
                            NTSTATUS copy_status = MmCopyVirtualMemory(
                                target_process,
                                reinterpret_cast<PVOID>(scan_ptr),
                                PsGetCurrentProcess(),
                                chunk_buffer,
                                read_with_overlap,
                                KernelMode,
                                &bytes_read
                            );

                            if (NT_SUCCESS(copy_status) && bytes_read >= pattern_length)
                            {
                                SIZE_T search_limit = bytes_read - pattern_length;
                                for (SIZE_T offset = 0; offset <= search_limit; ++offset)
                                {
                                    if (MatchMask(chunk_buffer + offset, pattern, mask, pattern_length))
                                    {
                                        PVOID match_addr = reinterpret_cast<PVOID>(scan_ptr + offset);
                                        if (first_match == nullptr)
                                            first_match = match_addr;
                                        total_matches++;
                                    }
                                }
                            }

                            scan_ptr += to_read;
                        }
                    }

                    current_va = region_end;
                }

                helper::allocate::kernelmode::FreeKernelMemory(chunk_buffer);
                ObDereferenceObject(target_process);

                *first_match_address = first_match;
                *matches_count = total_matches;

                return STATUS_SUCCESS;
            }
        }
    }

    namespace read
{
    namespace process
    {
        //
        // =========================================================
        // String information
        // =========================================================
        //

        typedef enum _READ_STRING_ENCODING
        {
            ReadStringAnsi = 1,
            ReadStringUnicode = 2

        } READ_STRING_ENCODING;


        typedef struct _READ_STRING_INFORMATION
        {
            //
            // Original address inside TargetProcess.
            //
            PVOID StringAddress;

            //
            // User VA inside RequestProcess containing
            // a copy of the actual string.
            //
            PVOID DumpedAddress;

            //
            // Size in bytes, excluding terminating NULL.
            //
            SIZE_T StringSize;

            READ_STRING_ENCODING Encoding;

        } READ_STRING_INFORMATION,
          *PREAD_STRING_INFORMATION;



        //
        // =========================================================
        // Internal protection helper
        // =========================================================
        //

        inline BOOLEAN IsReadableProtection(
            _In_ ULONG protect
        )
        {
            if (
                protect == 0 ||
                (protect & PAGE_GUARD) != 0 ||
                (protect & PAGE_NOACCESS) != 0
                )
            {
                return FALSE;
            }

            ULONG base_protect =
                protect & 0xFF;

            switch (base_protect)
            {
                case PAGE_READONLY:
                case PAGE_READWRITE:
                case PAGE_WRITECOPY:
                case PAGE_EXECUTE_READ:
                case PAGE_EXECUTE_READWRITE:
                case PAGE_EXECUTE_WRITECOPY:
                    return TRUE;

                default:
                    return FALSE;
            }
        }


        inline BOOLEAN IsWritableProtection(
            _In_ ULONG protect
        )
        {
            ULONG base_protect =
                protect & 0xFF;

            switch (base_protect)
            {
                case PAGE_READWRITE:
                case PAGE_WRITECOPY:
                case PAGE_EXECUTE_READWRITE:
                case PAGE_EXECUTE_WRITECOPY:
                    return TRUE;

                default:
                    return FALSE;
            }
        }


        inline BOOLEAN IsExecutableProtection(
            _In_ ULONG protect
        )
        {
            ULONG base_protect =
                protect & 0xFF;

            switch (base_protect)
            {
                case PAGE_EXECUTE:
                case PAGE_EXECUTE_READ:
                case PAGE_EXECUTE_READWRITE:
                case PAGE_EXECUTE_WRITECOPY:
                    return TRUE;

                default:
                    return FALSE;
            }
        }



        //
        // =========================================================
        // ReadProcess
        //
        // TargetProcess:
        //
        //     read_address
        //          ↓
        //       [DATA]
        //
        //          ↓
        //     kernel temporary buffer
        //
        //          ↓
        //
        // RequestProcess:
        //
        //     newly allocated User VA
        //
        // =========================================================
        //

        inline NTSTATUS ReadProcess(
            _In_ HANDLE request_process_handle,
            _In_ HANDLE target_process_handle,
            _In_ PVOID read_address,
            _In_ ULONGLONG size,
            _Out_ PUCHAR* output_readed_address_in_request
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            if (
                request_process_handle == nullptr ||
                target_process_handle == nullptr ||
                read_address == nullptr ||
                size == 0 ||
                output_readed_address_in_request == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }

            *output_readed_address_in_request =
                nullptr;


            if (
                size >
                static_cast<ULONGLONG>(MAXSIZE_T)
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            SIZE_T read_size =
                static_cast<SIZE_T>(size);


            //
            // Target EPROCESS
            //

            PEPROCESS target_process =
                nullptr;

            NTSTATUS status =
                ObReferenceObjectByHandle(
                    target_process_handle,
                    PROCESS_VM_READ,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(
                        &target_process
                    ),
                    nullptr
                );

            if (!NT_SUCCESS(status))
                return status;


            //
            // Temporary kernel buffer.
            //

            PUCHAR kernel_buffer =
                static_cast<PUCHAR>(
                    helper::allocate::kernelmode::
                    AllocateKernelMemory(
                        read_size
                    )
                );


            if (kernel_buffer == nullptr)
            {
                ObDereferenceObject(
                    target_process
                );

                return STATUS_INSUFFICIENT_RESOURCES;
            }


            //
            // -----------------------------------------------------
            // 1. TargetProcess -> KernelBuffer
            // -----------------------------------------------------
            //

            SIZE_T copied_size =
                0;


            status =
                MmCopyVirtualMemory(
                    target_process,
                    read_address,

                    PsGetCurrentProcess(),
                    kernel_buffer,

                    read_size,
                    KernelMode,
                    &copied_size
                );


            if (
                !NT_SUCCESS(status) ||
                copied_size != read_size
                )
            {
                helper::allocate::kernelmode::
                    FreeKernelMemory(
                        kernel_buffer
                    );

                ObDereferenceObject(
                    target_process
                );

                return NT_SUCCESS(status)
                    ? STATUS_PARTIAL_COPY
                    : status;
            }


            //
            // -----------------------------------------------------
            // 2. Allocate User VA inside RequestProcess.
            // -----------------------------------------------------
            //

            PVOID request_user_buffer =
                nullptr;


            status =
                helper::allocate::usermode::
                AllocVirtualMemory(
                    request_process_handle,
                    read_size,
                    PAGE_READWRITE,
                    &request_user_buffer
                );


            if (!NT_SUCCESS(status))
            {
                helper::allocate::kernelmode::
                    FreeKernelMemory(
                        kernel_buffer
                    );

                ObDereferenceObject(
                    target_process
                );

                return status;
            }


            //
            // Resolve RequestProcess EPROCESS.
            //

            PEPROCESS request_process =
                nullptr;


            status =
                ObReferenceObjectByHandle(
                    request_process_handle,
                    PROCESS_VM_WRITE |
                    PROCESS_VM_OPERATION,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(
                        &request_process
                    ),
                    nullptr
                );


            if (!NT_SUCCESS(status))
            {
                helper::allocate::usermode::
                    FreeVirtualMemory(
                        request_process_handle,
                        request_user_buffer
                    );

                helper::allocate::kernelmode::
                    FreeKernelMemory(
                        kernel_buffer
                    );

                ObDereferenceObject(
                    target_process
                );

                return status;
            }


            //
            // -----------------------------------------------------
            // 3. KernelBuffer -> RequestProcess User VA
            // -----------------------------------------------------
            //

            BOOLEAN write_success =
                FALSE;


            KAPC_STATE apc_state = {};


            KeStackAttachProcess(
                request_process,
                &apc_state
            );


            __try
            {
                ProbeForWrite(
                    request_user_buffer,
                    read_size,
                    sizeof(UCHAR)
                );


                RtlCopyMemory(
                    request_user_buffer,
                    kernel_buffer,
                    read_size
                );


                write_success =
                    TRUE;
            }
            __except (
                EXCEPTION_EXECUTE_HANDLER
                )
            {
                write_success =
                    FALSE;

                status =
                    GetExceptionCode();
            }


            KeUnstackDetachProcess(
                &apc_state
            );


            ObDereferenceObject(
                request_process
            );

            ObDereferenceObject(
                target_process
            );


            helper::allocate::kernelmode::
                FreeKernelMemory(
                    kernel_buffer
                );


            if (!write_success)
            {
                helper::allocate::usermode::
                    FreeVirtualMemory(
                        request_process_handle,
                        request_user_buffer
                    );

                return status;
            }


            *output_readed_address_in_request =
                static_cast<PUCHAR>(
                    request_user_buffer
                );


            return STATUS_SUCCESS;
        }



        //
        // =========================================================
        // Internal helper:
        //
        // Save one discovered string to RequestProcess.
        // =========================================================
        //

        inline BOOLEAN SaveStringResult(
            _In_ HANDLE request_process_handle,
            _In_ PVOID target_string_address,
            _In_reads_bytes_(string_size) PUCHAR string_data,
            _In_ SIZE_T string_size,
            _In_ READ_STRING_ENCODING encoding,
            _Inout_ PVOID* first_node,
            _Inout_ PVOID* latest_node
        )
        {
            if (
                string_data == nullptr ||
                string_size == 0 ||
                first_node == nullptr ||
                latest_node == nullptr
                )
            {
                return FALSE;
            }


            //
            // Allocate dumped actual String in RequestProcess.
            //
            SIZE_T terminator_size =
                (
                    encoding ==
                    ReadStringUnicode
                )
                ? sizeof(WCHAR)
                : sizeof(CHAR);


            if (
                string_size >
                MAXSIZE_T -
                terminator_size
                )
            {
                return FALSE;
            }


            SIZE_T allocation_size =
                string_size +
                terminator_size;


            PVOID dumped_address =
                nullptr;


            NTSTATUS status =
                helper::allocate::usermode::
                AllocVirtualMemory(
                    request_process_handle,
                    allocation_size,
                    PAGE_READWRITE,
                    &dumped_address
                );


            if (!NT_SUCCESS(status))
                return FALSE;


            //
            // Copy actual string into RequestProcess.
            //

            PEPROCESS request_process =
                nullptr;


            status =
                ObReferenceObjectByHandle(
                    request_process_handle,
                    PROCESS_VM_WRITE |
                    PROCESS_VM_OPERATION,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(
                        &request_process
                    ),
                    nullptr
                );


            if (!NT_SUCCESS(status))
            {
                helper::allocate::usermode::
                    FreeVirtualMemory(
                        request_process_handle,
                        dumped_address
                    );

                return FALSE;
            }


            BOOLEAN success =
                FALSE;


            KAPC_STATE apc_state = {};


            KeStackAttachProcess(
                request_process,
                &apc_state
            );


            __try
            {
                ProbeForWrite(
                    dumped_address,
                    allocation_size,
                    sizeof(UCHAR)
                );


                RtlCopyMemory(
                    dumped_address,
                    string_data,
                    string_size
                );


                //
                // Allocation from Ex/Zw is already zeroed,
                // but explicitly terminate the copied string.
                //

                if (
                    encoding ==
                    ReadStringUnicode
                    )
                {
                    *reinterpret_cast<WCHAR*>(
                        reinterpret_cast<PUCHAR>(
                            dumped_address
                        ) +
                        string_size
                    ) = L'\0';
                }
                else
                {
                    *reinterpret_cast<CHAR*>(
                        reinterpret_cast<PUCHAR>(
                            dumped_address
                        ) +
                        string_size
                    ) = '\0';
                }


                success =
                    TRUE;
            }
            __except (
                EXCEPTION_EXECUTE_HANDLER
                )
            {
                success =
                    FALSE;
            }


            KeUnstackDetachProcess(
                &apc_state
            );


            ObDereferenceObject(
                request_process
            );


            if (!success)
            {
                helper::allocate::usermode::
                    FreeVirtualMemory(
                        request_process_handle,
                        dumped_address
                    );

                return FALSE;
            }


            READ_STRING_INFORMATION information = {};

            information.StringAddress =
                target_string_address;

            information.DumpedAddress =
                dumped_address;

            information.StringSize =
                string_size;

            information.Encoding =
                encoding;


            //
            // Linked-list Data contains READ_STRING_INFORMATION.
            //

            PVOID new_node =
                helper::linkedlist::usermode::
                InsertList(
                    request_process_handle,
                    *latest_node,
                    reinterpret_cast<PUCHAR>(
                        &information
                    ),
                    sizeof(
                        READ_STRING_INFORMATION
                    )
                );


            if (new_node == nullptr)
            {
                helper::allocate::usermode::
                    FreeVirtualMemory(
                        request_process_handle,
                        dumped_address
                    );

                return FALSE;
            }


            *latest_node =
                new_node;


            if (*first_node == nullptr)
            {
                *first_node =
                    new_node;
            }


            return TRUE;
        }



        //
        // =========================================================
        // ReadStringProcess
        //
        // Scans readable committed memory.
        //
        // Minimum string length is configurable.
        //
        // ANSI:
        //     printable ASCII bytes
        //
        // Unicode:
        //     UTF-16 printable characters, including Korean range.
        // =========================================================
        //

        inline NTSTATUS FreeStringResultList(
            _In_ HANDLE request_process_handle,
            _In_opt_ PVOID first_node_address
        )
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;


            if (request_process_handle == nullptr)
                return STATUS_INVALID_PARAMETER;


            if (first_node_address == nullptr)
                return STATUS_SUCCESS;


            PEPROCESS request_process =
                nullptr;


            NTSTATUS status =
                ObReferenceObjectByHandle(
                    request_process_handle,
                    0,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(
                        &request_process
                        ),
                    nullptr
                );


            if (!NT_SUCCESS(status))
                return status;


            PVOID current_address =
                first_node_address;


            PVOID expected_previous =
                nullptr;

            ULONG nodes_processed = 0;
            constexpr ULONG MAX_STRING_NODES = helper::linkedlist::MAX_USER_RESULT_NODES;

            for (;;)
            {
                if (current_address == nullptr || ++nodes_processed > MAX_STRING_NODES)
                    break;


                helper::linkedlist::LINKED_LIST_NODE
                    node = {};


                helper::read::process::
                    READ_STRING_INFORMATION
                    string_information = {};


                BOOLEAN read_success =
                    FALSE;


                KAPC_STATE apc_state = {};


                KeStackAttachProcess(
                    request_process,
                    &apc_state
                );


                __try
                {
                    ProbeForRead(
                        current_address,
                        sizeof(
                            helper::linkedlist::
                            LINKED_LIST_NODE
                            ),
                        __alignof(
                            helper::linkedlist::
                            LINKED_LIST_NODE
                            )
                    );


                    RtlCopyMemory(
                        &node,
                        current_address,
                        sizeof(node)
                    );


                    if (
                        node.Signature !=
                        helper::linkedlist::
                        LINKED_LIST_SIGNATURE
                        )
                    {
                        __leave;
                    }


                    if (
                        node.Previous !=
                        expected_previous
                        )
                    {
                        __leave;
                    }


                    if (
                        node.Data ==
                        nullptr
                        )
                    {
                        __leave;
                    }


                    ProbeForRead(
                        node.Data,
                        sizeof(
                            helper::read::process::
                            READ_STRING_INFORMATION
                            ),
                        __alignof(
                            helper::read::process::
                            READ_STRING_INFORMATION
                            )
                    );


                    RtlCopyMemory(
                        &string_information,
                        node.Data,
                        sizeof(
                            string_information
                            )
                    );


                    read_success =
                        TRUE;
                }
                __except (
                    EXCEPTION_EXECUTE_HANDLER
                    )
                {
                    read_success =
                        FALSE;
                }


                KeUnstackDetachProcess(
                    &apc_state
                );


                if (!read_success)
                {
                    status =
                        STATUS_DATA_ERROR;

                    break;
                }


                PVOID next_address =
                    node.Next;


                if (
                    string_information.DumpedAddress !=
                    nullptr
                    )
                {
                    NTSTATUS free_status =
                        helper::allocate::usermode::
                        FreeVirtualMemory(
                            request_process_handle,
                            string_information.DumpedAddress
                        );


                    if (
                        !NT_SUCCESS(free_status) &&
                        NT_SUCCESS(status)
                        )
                    {
                        status =
                            free_status;
                    }
                }


                expected_previous =
                    current_address;

                current_address =
                    next_address;
            }


            ObDereferenceObject(
                request_process
            );


            if (!NT_SUCCESS(status))
                return status;


            return
                helper::linkedlist::usermode::
                FreeLinkedList(
                    request_process_handle,
                    first_node_address
                );
        }

        inline PVOID ReadStringProcess(
            _In_ HANDLE request_process_handle,
            _In_ HANDLE target_process_handle,
            _In_ SIZE_T minimum_character_count = 4,
            _Out_opt_ NTSTATUS* result_status = nullptr
        )
        {
            if (result_status) *result_status = STATUS_UNSUCCESSFUL;
            ULONG result_count = 0;
            NTSTATUS scan_status = STATUS_SUCCESS;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return nullptr;


            if (
                request_process_handle == nullptr ||
                target_process_handle == nullptr ||
                minimum_character_count == 0
                )
            {
                return nullptr;
            }


            constexpr SIZE_T CHUNK_SIZE =
                0x10000;


            PUCHAR scan_buffer =
                static_cast<PUCHAR>(
                    helper::allocate::kernelmode::
                    AllocateKernelMemory(
                        CHUNK_SIZE
                    )
                );


            if (scan_buffer == nullptr)
                return nullptr;


            PEPROCESS target_process =
                nullptr;


            NTSTATUS status =
                ObReferenceObjectByHandle(
                    target_process_handle,
                    PROCESS_QUERY_INFORMATION |
                    PROCESS_VM_READ,
                    *PsProcessType,
                    KernelMode,
                    reinterpret_cast<PVOID*>(
                        &target_process
                    ),
                    nullptr
                );


            if (!NT_SUCCESS(status))
            {
                helper::allocate::kernelmode::
                    FreeKernelMemory(
                        scan_buffer
                    );

                return nullptr;
            }


            PVOID first_node =
                nullptr;

            PVOID latest_node =
                nullptr;


            ULONG_PTR query_address =
                0;


            const ULONG_PTR highest_user =
                reinterpret_cast<ULONG_PTR>(
                    MmHighestUserAddress
                );


            while (
                query_address <=
                highest_user
                )
            {
                MEMORY_BASIC_INFORMATION mbi = {};

                SIZE_T return_length =
                    0;


                status =
                    ZwQueryVirtualMemory(
                        target_process_handle,
                        reinterpret_cast<PVOID>(
                            query_address
                        ),
                        MemoryBasicInformation,
                        &mbi,
                        sizeof(mbi),
                        &return_length
                    );


                if (!NT_SUCCESS(status))
                    break;


                ULONG_PTR region_base =
                    reinterpret_cast<ULONG_PTR>(
                        mbi.BaseAddress
                    );


                if (
                    mbi.RegionSize == 0 ||
                    region_base >
                    MAXULONG_PTR -
                    mbi.RegionSize
                    )
                {
                    break;
                }


                ULONG_PTR next_region =
                    region_base +
                    mbi.RegionSize;


                if (
                    mbi.State ==
                    MEM_COMMIT &&
                    IsReadableProtection(
                        mbi.Protect
                    )
                    )
                {
                    SIZE_T offset =
                        0;


                    while (
                        offset <
                        mbi.RegionSize
                        )
                    {
                        SIZE_T remaining =
                            mbi.RegionSize -
                            offset;


                        SIZE_T read_size =
                            (
                                remaining >
                                CHUNK_SIZE
                            )
                            ? CHUNK_SIZE
                            : remaining;


                        PVOID target_address =
                            reinterpret_cast<PVOID>(
                                region_base +
                                offset
                            );


                        SIZE_T copied =
                            0;


                        status =
                            MmCopyVirtualMemory(
                                target_process,
                                target_address,

                                PsGetCurrentProcess(),
                                scan_buffer,

                                read_size,
                                KernelMode,
                                &copied
                            );


                        if (
                            NT_SUCCESS(status) &&
                            copied > 0
                            )
                        {
                            //
                            // -----------------------------------------
                            // ANSI / ASCII-like scan
                            // -----------------------------------------
                            //

                            SIZE_T index =
                                0;


                            while (
                                index <
                                copied
                                )
                            {
                                SIZE_T start =
                                    index;


                                while (
                                    index <
                                    copied
                                    )
                                {
                                    UCHAR value =
                                        scan_buffer[index];


                                    BOOLEAN readable =
                                        (
                                            value >=
                                                0x20 &&
                                            value <=
                                                0x7E
                                        );


                                    if (!readable)
                                        break;


                                    ++index;
                                }


                                SIZE_T count =
                                    index -
                                    start;


                                if (
                                    count >=
                                    minimum_character_count
                                    )
                                {
                                    PVOID string_address =
                                        reinterpret_cast<PVOID>(
                                            region_base +
                                            offset +
                                            start
                                        );


                                    if (result_count >= helper::linkedlist::MAX_USER_RESULT_NODES)
                                    {
                                        scan_status = STATUS_QUOTA_EXCEEDED;
                                        goto Cleanup;
                                    }
                                    ++result_count;
                                    if (
                                        !SaveStringResult(
                                            request_process_handle,
                                            string_address,
                                            scan_buffer +
                                                start,
                                            count,
                                            ReadStringAnsi,
                                            &first_node,
                                            &latest_node
                                        )
                                        )
                                    {
                                        scan_status = STATUS_INSUFFICIENT_RESOURCES;
                                        goto Cleanup;
                                    }
                                }


                                ++index;
                            }


                            //
                            // -----------------------------------------
                            // UTF-16 scan
                            //
                            // Includes ordinary printable characters,
                            // Hangul, CJK, etc.
                            // -----------------------------------------
                            //

                            SIZE_T wchar_count =
                                copied /
                                sizeof(WCHAR);


                            PWCHAR unicode_buffer =
                                reinterpret_cast<PWCHAR>(
                                    scan_buffer
                                );


                            SIZE_T wchar_index =
                                0;


                            while (
                                wchar_index <
                                wchar_count
                                )
                            {
                                SIZE_T start =
                                    wchar_index;


                                while (
                                    wchar_index <
                                    wchar_count
                                    )
                                {
                                    WCHAR ch =
                                        unicode_buffer[
                                            wchar_index
                                        ];


                                    BOOLEAN readable =
                                        FALSE;


                                    if (
                                        ch >=
                                        0x20 &&
                                        ch !=
                                        0x7F
                                        )
                                    {
                                        //
                                        // Reject control/surrogate
                                        // values.
                                        //
                                        if (
                                            !(ch >= 0xD800 &&
                                              ch <= 0xDFFF)
                                            )
                                        {
                                            readable =
                                                TRUE;
                                        }
                                    }


                                    if (!readable)
                                        break;


                                    ++wchar_index;
                                }


                                SIZE_T count =
                                    wchar_index -
                                    start;


                                if (
                                    count >=
                                    minimum_character_count
                                    )
                                {
                                    SIZE_T byte_size =
                                        count *
                                        sizeof(WCHAR);


                                    PVOID string_address =
                                        reinterpret_cast<PVOID>(
                                            region_base +
                                            offset +
                                            (
                                                start *
                                                sizeof(WCHAR)
                                            )
                                        );


                                    if (result_count >= helper::linkedlist::MAX_USER_RESULT_NODES)
                                    {
                                        scan_status = STATUS_QUOTA_EXCEEDED;
                                        goto Cleanup;
                                    }
                                    ++result_count;
                                    if (
                                        !SaveStringResult(
                                            request_process_handle,
                                            string_address,
                                            reinterpret_cast<PUCHAR>(
                                                &unicode_buffer[
                                                    start
                                                ]
                                            ),
                                            byte_size,
                                            ReadStringUnicode,
                                            &first_node,
                                            &latest_node
                                        )
                                        )
                                    {
                                        scan_status = STATUS_INSUFFICIENT_RESOURCES;
                                        goto Cleanup;
                                    }
                                }


                                ++wchar_index;
                            }
                        }


                        offset +=
                            read_size;
                    }
                }


                if (
                    next_region <=
                    query_address
                    )
                {
                    break;
                }


                query_address =
                    next_region;
            }


        Cleanup:

            helper::allocate::kernelmode::
                FreeKernelMemory(
                    scan_buffer
                );


            ObDereferenceObject(
                target_process
            );


            if (!NT_SUCCESS(scan_status))
            {
                NTSTATUS release_status = FreeStringResultList(request_process_handle, first_node);
                if (!NT_SUCCESS(release_status)) scan_status = release_status;
                first_node = nullptr;
            }
            if (result_status) *result_status = first_node ? STATUS_SUCCESS :
                (NT_SUCCESS(scan_status) ? STATUS_NOT_FOUND : scan_status);
            return first_node;
        }



        // ============================================================
            // Constants
            // ============================================================

        constexpr ULONG MEMORY_IMAGE_NAME_LENGTH = 260;
        constexpr ULONG MEMORY_IMAGE_PATH_LENGTH = 520;

        constexpr ULONG MAX_PROCESS_MODULE_COUNT = 4096;


        // ============================================================
        // UserMode result structure
        //
        // This entire structure is copied into requester UserMode VA.
        //
        // No pointer inside this structure points to TargetProcess
        // strings.
        // ============================================================

        typedef struct _READ_PROCESS_MEMORY_AREA_INFORMATION
        {
            //
            // --------------------------------------------------------
            // Region
            // --------------------------------------------------------
            //

            PVOID BaseAddress;

            PVOID AllocationBase;

            SIZE_T RegionSize;


            ULONG AllocationProtect;

            ULONG Protect;

            ULONG State;

            ULONG Type;


            //
            // --------------------------------------------------------
            // Generic memory flags
            // --------------------------------------------------------
            //

            BOOLEAN IsCommitted;

            BOOLEAN IsReadable;

            BOOLEAN IsWritable;

            BOOLEAN IsExecutable;

            BOOLEAN IsGuarded;

            BOOLEAN IsPrivate;

            BOOLEAN IsMapped;

            BOOLEAN IsImage;


            //
            // --------------------------------------------------------
            // Image / Module flags
            // --------------------------------------------------------
            //

            BOOLEAN HasImageInformation;

            BOOLEAN HasPeHeaderInformation;

            BOOLEAN IsImageBase;

            BOOLEAN IsMainImage;

            UCHAR ReservedFlags[4];


            //
            // --------------------------------------------------------
            // Image / Module metadata
            // --------------------------------------------------------
            //

            PVOID ImageBaseAddress;

            SIZE_T ImageSize;

            SIZE_T ImageRegionOffset;


            ULONG ImageTimeDateStamp;

            ULONG ImageCheckSum;


            //
            // --------------------------------------------------------
            // Self-contained strings
            // --------------------------------------------------------
            //

            WCHAR ImageName[
                MEMORY_IMAGE_NAME_LENGTH
            ];

            WCHAR ImagePath[
                MEMORY_IMAGE_PATH_LENGTH
            ];

        } READ_PROCESS_MEMORY_AREA_INFORMATION,
            * PREAD_PROCESS_MEMORY_AREA_INFORMATION;


        // ============================================================
        // Internal MEMORY snapshot node
        // ============================================================

        typedef struct _PROCESS_MEMORY_SNAPSHOT_ENTRY
        {
            LIST_ENTRY ListEntry;

            READ_PROCESS_MEMORY_AREA_INFORMATION Information;

        } PROCESS_MEMORY_SNAPSHOT_ENTRY,
            * PPROCESS_MEMORY_SNAPSHOT_ENTRY;


        // ============================================================
        // Internal MODULE snapshot
        // ============================================================

        typedef struct _PROCESS_MODULE_SNAPSHOT_ENTRY
        {
            LIST_ENTRY ListEntry;

            PVOID DllBase;

            SIZE_T SizeOfImage;

            ULONG TimeDateStamp;

            ULONG CheckSum;

            BOOLEAN IsMainImage;

            BOOLEAN HasPeHeaderInformation;

            UCHAR Reserved[6];


            WCHAR BaseDllName[
                MEMORY_IMAGE_NAME_LENGTH
            ];

            WCHAR FullDllName[
                MEMORY_IMAGE_PATH_LENGTH
            ];

        } PROCESS_MODULE_SNAPSHOT_ENTRY,
            * PPROCESS_MODULE_SNAPSHOT_ENTRY;


        // ============================================================
        // x64 Loader views
        //
        // These intentionally use only the fields required by helper.
        //
        // Microsoft documents PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY as
        // structures that may change in future versions of Windows.
        // ============================================================

        typedef struct _HELPER_PEB_LDR_DATA_VIEW64
        {
            UCHAR Reserved1[8];

            PVOID Reserved2[3];

            LIST_ENTRY InMemoryOrderModuleList;

        } HELPER_PEB_LDR_DATA_VIEW64,
            * PHELPER_PEB_LDR_DATA_VIEW64;


        typedef struct _HELPER_LDR_DATA_TABLE_ENTRY_VIEW64
        {
            PVOID Reserved1[2];

            LIST_ENTRY InMemoryOrderLinks;

            PVOID Reserved2[2];

            PVOID DllBase;

            PVOID Reserved3[2];

            UNICODE_STRING FullDllName;

            UCHAR Reserved4[8];

            PVOID Reserved5[3];

            union
            {
                ULONG CheckSum;

                PVOID Reserved6;
            };

            ULONG TimeDateStamp;

        } HELPER_LDR_DATA_TABLE_ENTRY_VIEW64,
            * PHELPER_LDR_DATA_TABLE_ENTRY_VIEW64;


        // ============================================================
        // Minimal x64 PEB view
        //
        // Ldr is at +0x18 on native x64 PEB.
        // ============================================================

        typedef struct _HELPER_PEB_VIEW64
        {
            UCHAR Reserved[0x18];

            PHELPER_PEB_LDR_DATA_VIEW64 Ldr;

        } HELPER_PEB_VIEW64,
            * PHELPER_PEB_VIEW64;


        


        


        // ============================================================
        // User pointer validation
        // ============================================================

        inline BOOLEAN IsUserAddress(
            _In_opt_ PVOID address
        )
        {
            if (address == nullptr)
                return FALSE;


            return (
                reinterpret_cast<ULONG_PTR>(
                    address
                    )
                <=
                reinterpret_cast<ULONG_PTR>(
                    MmHighestUserAddress
                    )
                );
        }


        inline BOOLEAN IsUserRange(
            _In_opt_ PVOID address,
            _In_ SIZE_T size
        )
        {
            if (
                address == nullptr ||
                size == 0
                )
            {
                return FALSE;
            }


            const ULONG_PTR start =
                reinterpret_cast<ULONG_PTR>(
                    address
                    );


            const ULONG_PTR highest =
                reinterpret_cast<ULONG_PTR>(
                    MmHighestUserAddress
                    );


            if (
                start >
                highest
                )
            {
                return FALSE;
            }


            if (
                size - 1 >
                highest - start
                )
            {
                return FALSE;
            }


            return TRUE;
        }


        // ============================================================
        // Fixed WCHAR helpers
        // ============================================================

        inline VOID ClearWideBuffer(
            _Out_writes_(count) PWCHAR buffer,
            _In_ SIZE_T count
        )
        {
            if (
                buffer == nullptr ||
                count == 0
                )
            {
                return;
            }


            RtlZeroMemory(
                buffer,
                count * sizeof(WCHAR)
            );
        }


        inline VOID ExtractBaseName(
            _In_reads_(source_count) PCWCHAR source,
            _In_ SIZE_T source_count,

            _Out_writes_(destination_count) PWCHAR destination,
            _In_ SIZE_T destination_count
        )
        {
            if (
                source == nullptr ||
                destination == nullptr ||
                destination_count == 0
                )
            {
                return;
            }


            destination[0] =
                L'\0';


            SIZE_T actual_length =
                0;


            while (
                actual_length <
                source_count &&
                source[actual_length] !=
                L'\0'
                )
            {
                ++actual_length;
            }


            if (
                actual_length == 0
                )
            {
                return;
            }


            SIZE_T start =
                0;


            for (
                SIZE_T index = 0;

                index <
                actual_length;

                ++index
                )
            {
                if (
                    source[index] ==
                    L'\\' ||
                    source[index] ==
                    L'/'
                    )
                {
                    start =
                        index + 1;
                }
            }


            SIZE_T copy_count =
                actual_length -
                start;


            if (
                copy_count >=
                destination_count
                )
            {
                copy_count =
                    destination_count - 1;
            }


            if (
                copy_count != 0
                )
            {
                RtlCopyMemory(
                    destination,

                    source + start,

                    copy_count *
                    sizeof(WCHAR)
                );
            }


            destination[
                copy_count
            ] = L'\0';
        }


        // ============================================================
        // TargetProcess UNICODE_STRING -> Kernel fixed buffer
        //
        // Must be called while attached to TargetProcess.
        // ============================================================

        inline NTSTATUS CopyTargetUnicodeString(
            _In_ const UNICODE_STRING* source,

            _Out_writes_(destination_count)
            PWCHAR destination,

            _In_ SIZE_T destination_count
        )
        {
            if (
                source == nullptr ||
                destination == nullptr ||
                destination_count == 0
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            destination[0] =
                L'\0';


            if (
                source->Buffer == nullptr ||
                source->Length == 0
                )
            {
                return STATUS_SUCCESS;
            }


            if (
                source->Length >
                source->MaximumLength
                )
            {
                return STATUS_DATA_ERROR;
            }


            if (
                (
                    source->Length %
                    sizeof(WCHAR)
                    ) != 0
                )
            {
                return STATUS_DATA_ERROR;
            }


            SIZE_T character_count =
                source->Length /
                sizeof(WCHAR);


            if (
                character_count >=
                destination_count
                )
            {
                character_count =
                    destination_count - 1;
            }


            const SIZE_T copy_size =
                character_count *
                sizeof(WCHAR);


            if (
                !IsUserRange(
                    source->Buffer,
                    copy_size
                )
                )
            {
                return STATUS_ACCESS_VIOLATION;
            }


            __try
            {
                ProbeForRead(
                    source->Buffer,

                    copy_size,

                    sizeof(WCHAR)
                );


                RtlCopyMemory(
                    destination,

                    source->Buffer,

                    copy_size
                );


                destination[
                    character_count
                ] = L'\0';
            }
            __except (
                EXCEPTION_EXECUTE_HANDLER
                )
            {
                return GetExceptionCode();
            }


            return STATUS_SUCCESS;
        }


        // ============================================================
        // PE Header information
        //
        // Must be called while attached to TargetProcess.
        // ============================================================

        inline NTSTATUS QueryImagePeHeader(
            _In_ PVOID image_base,

            _Out_ PSIZE_T image_size,

            _Out_ PULONG time_date_stamp,

            _Out_ PULONG check_sum
        )
        {
            if (
                image_base == nullptr ||
                image_size == nullptr ||
                time_date_stamp == nullptr ||
                check_sum == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            *image_size =
                0;

            *time_date_stamp =
                0;

            *check_sum =
                0;


            if (
                !IsUserRange(
                    image_base,

                    sizeof(
                        HELPER_IMAGE_DOS_HEADER
                        )
                )
                )
            {
                return STATUS_ACCESS_VIOLATION;
            }


            __try
            {
                //
                // ====================================================
                // DOS Header
                // ====================================================
                //

                ProbeForRead(
                    image_base,

                    sizeof(
                        HELPER_IMAGE_DOS_HEADER
                        ),

                    1
                );


                auto dos_header =
                    reinterpret_cast<
                    PHELPER_IMAGE_DOS_HEADER
                    >(
                        image_base
                        );


                if (
                    dos_header->e_magic !=
                    HELPER_IMAGE_DOS_SIGNATURE
                    )
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }


                if (
                    dos_header->e_lfanew <= 0
                    )
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }


                //
                // ====================================================
                // NT Header address
                // ====================================================
                //

                const ULONG_PTR base =
                    reinterpret_cast<
                    ULONG_PTR
                    >(
                        image_base
                        );


                const ULONG_PTR nt_offset =
                    static_cast<
                    ULONG_PTR
                    >(
                        dos_header->e_lfanew
                        );


                if (
                    nt_offset >
                    MAXULONG_PTR - base
                    )
                {
                    return STATUS_INTEGER_OVERFLOW;
                }


                const ULONG_PTR nt_address =
                    base +
                    nt_offset;


                auto nt_headers =
                    reinterpret_cast<
                    PHELPER_IMAGE_NT_HEADERS64
                    >(
                        nt_address
                        );


                if (
                    !IsUserRange(
                        nt_headers,

                        sizeof(
                            HELPER_IMAGE_NT_HEADERS64
                            )
                    )
                    )
                {
                    return STATUS_ACCESS_VIOLATION;
                }


                ProbeForRead(
                    nt_headers,

                    sizeof(
                        HELPER_IMAGE_NT_HEADERS64
                        ),

                    1
                );


                //
                // ====================================================
                // PE Signature
                // ====================================================
                //

                if (
                    nt_headers->Signature !=
                    HELPER_IMAGE_NT_SIGNATURE
                    )
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }


                //
                // ====================================================
                // Optional Header Magic
                // ====================================================
                //

                if (
                    nt_headers
                    ->OptionalHeader
                    .Magic !=
                    HELPER_IMAGE_NT_OPTIONAL_HDR64_MAGIC
                    )
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }


                //
                // ====================================================
                // Sanity checks
                // ====================================================
                //

                if (
                    nt_headers
                    ->OptionalHeader
                    .SizeOfImage == 0
                    )
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }


                if (
                    nt_headers
                    ->FileHeader
                    .NumberOfSections == 0
                    )
                {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }


                //
                // ====================================================
                // Result
                // ====================================================
                //

                *image_size =
                    static_cast<SIZE_T>(
                        nt_headers
                        ->OptionalHeader
                        .SizeOfImage
                        );


                *time_date_stamp =
                    nt_headers
                    ->FileHeader
                    .TimeDateStamp;


                *check_sum =
                    nt_headers
                    ->OptionalHeader
                    .CheckSum;


                return STATUS_SUCCESS;
            }
            __except (
                EXCEPTION_EXECUTE_HANDLER
                )
            {
                return GetExceptionCode();
            }
        }


        // ============================================================
        // Free Memory Snapshot
        // ============================================================

        inline VOID FreeMemorySnapshot(
            _Inout_ PLIST_ENTRY list_head
        )
        {
            if (
                list_head == nullptr
                )
            {
                return;
            }


            while (
                !IsListEmpty(
                    list_head
                )
                )
            {
                PLIST_ENTRY entry =
                    RemoveHeadList(
                        list_head
                    );


                auto snapshot =
                    CONTAINING_RECORD(
                        entry,

                        PROCESS_MEMORY_SNAPSHOT_ENTRY,

                        ListEntry
                    );


                helper::allocate::kernelmode::
                    FreeKernelMemory(
                        snapshot
                    );
            }
        }


        // ============================================================
        // Free Module Snapshot
        // ============================================================

        inline VOID FreeModuleSnapshot(
            _Inout_ PLIST_ENTRY list_head
        )
        {
            if (
                list_head == nullptr
                )
            {
                return;
            }


            while (
                !IsListEmpty(
                    list_head
                )
                )
            {
                PLIST_ENTRY entry =
                    RemoveHeadList(
                        list_head
                    );


                auto snapshot =
                    CONTAINING_RECORD(
                        entry,

                        PROCESS_MODULE_SNAPSHOT_ENTRY,

                        ListEntry
                    );


                helper::allocate::kernelmode::
                    FreeKernelMemory(
                        snapshot
                    );
            }
        }


        // ============================================================
        // Build TargetProcess Memory Snapshot
        // ============================================================

        inline NTSTATUS BuildMemorySnapshot(
            _In_ HANDLE target_process_handle,

            _Out_ PLIST_ENTRY memory_list
        )
        {
            if (
                target_process_handle == nullptr ||
                memory_list == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            InitializeListHead(
                memory_list
            );


            ULONG_PTR current_address =
                0;


            const ULONG_PTR maximum_address =
                reinterpret_cast<ULONG_PTR>(
                    MmHighestUserAddress
                    );


            while (
                current_address <=
                maximum_address
                )
            {
                MEMORY_BASIC_INFORMATION mbi{};


                SIZE_T returned_length =
                    0;


                NTSTATUS status =
                    ZwQueryVirtualMemory(
                        target_process_handle,

                        reinterpret_cast<PVOID>(
                            current_address
                            ),

                        MemoryBasicInformation,

                        &mbi,

                        sizeof(mbi),

                        &returned_length
                    );


                if (
                    !NT_SUCCESS(status)
                    )
                {
                    //
                    // End of user VA map.
                    //
                    if (
                        status ==
                        STATUS_INVALID_PARAMETER
                        )
                    {
                        return STATUS_SUCCESS;
                    }


                    return status;
                }


                if (
                    mbi.RegionSize == 0
                    )
                {
                    return STATUS_DATA_ERROR;
                }


                const ULONG_PTR region_base =
                    reinterpret_cast<ULONG_PTR>(
                        mbi.BaseAddress
                        );


                if (
                    mbi.RegionSize >
                    MAXULONG_PTR -
                    region_base
                    )
                {
                    return STATUS_INTEGER_OVERFLOW;
                }


                const ULONG_PTR region_end =
                    region_base +
                    mbi.RegionSize;


                if (
                    region_end <=
                    region_base
                    )
                {
                    return STATUS_INTEGER_OVERFLOW;
                }


                auto snapshot =
                    reinterpret_cast<
                    PPROCESS_MEMORY_SNAPSHOT_ENTRY
                    >(
                        helper::allocate::kernelmode::
                        AllocateKernelMemory(
                            sizeof(
                                PROCESS_MEMORY_SNAPSHOT_ENTRY
                                )
                        )
                        );


                if (
                    snapshot == nullptr
                    )
                {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }


                RtlZeroMemory(
                    snapshot,
                    sizeof(*snapshot)
                );


                auto& info =
                    snapshot->Information;


                info.BaseAddress =
                    mbi.BaseAddress;


                info.AllocationBase =
                    mbi.AllocationBase;


                info.RegionSize =
                    mbi.RegionSize;


                info.AllocationProtect =
                    mbi.AllocationProtect;


                info.Protect =
                    mbi.Protect;


                info.State =
                    mbi.State;


                info.Type =
                    mbi.Type;


                //
                // ----------------------------------------------------
                // Flags
                // ----------------------------------------------------
                //

                info.IsCommitted =
                    (
                        mbi.State ==
                        MEM_COMMIT
                        );


                info.IsGuarded =
                    (
                        (
                            mbi.Protect &
                            PAGE_GUARD
                            ) != 0
                        );


                info.IsReadable =
                    (
                        info.IsCommitted &&
                        !info.IsGuarded &&
                        IsReadableProtection(
                            mbi.Protect
                        )
                        );


                info.IsWritable =
                    (
                        info.IsCommitted &&
                        !info.IsGuarded &&
                        IsWritableProtection(
                            mbi.Protect
                        )
                        );


                info.IsExecutable =
                    (
                        info.IsCommitted &&
                        !info.IsGuarded &&
                        IsExecutableProtection(
                            mbi.Protect
                        )
                        );


                info.IsPrivate =
                    (
                        mbi.Type ==
                        MEM_PRIVATE
                        );


                info.IsMapped =
                    (
                        mbi.Type ==
                        MEM_MAPPED
                        );


                info.IsImage =
                    (
                        mbi.Type ==
                        MEM_IMAGE
                        );


                //
                // ----------------------------------------------------
                // Basic MEM_IMAGE metadata
                //
                // Even if PEB loader matching fails, these fields
                // remain useful.
                // ----------------------------------------------------
                //

                if (
                    info.IsImage &&
                    info.AllocationBase != nullptr
                    )
                {
                    info.ImageBaseAddress =
                        info.AllocationBase;


                    info.IsImageBase =
                        (
                            info.BaseAddress ==
                            info.AllocationBase
                            );


                    const ULONG_PTR image_base =
                        reinterpret_cast<
                        ULONG_PTR
                        >(
                            info.AllocationBase
                            );


                    if (
                        region_base >=
                        image_base
                        )
                    {
                        info.ImageRegionOffset =
                            static_cast<SIZE_T>(
                                region_base -
                                image_base
                                );
                    }
                }


                InsertTailList(
                    memory_list,
                    &snapshot->ListEntry
                );


                if (
                    region_end >
                    maximum_address
                    )
                {
                    break;
                }


                current_address =
                    region_end;
            }


            return STATUS_SUCCESS;
        }


        // ============================================================
        // Calculate fallback image span from MEM_IMAGE regions
        //
        // Used even when Loader metadata is unavailable.
        // ============================================================

        inline VOID BuildFallbackImageSpans(
            _Inout_ PLIST_ENTRY memory_list
        )
        {
            if (
                memory_list == nullptr
                )
            {
                return;
            }


            for (
                PLIST_ENTRY current =
                memory_list->Flink;

                current !=
                memory_list;

                current =
                current->Flink
                )
            {
                auto snapshot =
                    CONTAINING_RECORD(
                        current,

                        PROCESS_MEMORY_SNAPSHOT_ENTRY,

                        ListEntry
                    );


                auto& info =
                    snapshot->Information;


                if (
                    !info.IsImage ||
                    info.AllocationBase == nullptr
                    )
                {
                    continue;
                }


                const ULONG_PTR image_base =
                    reinterpret_cast<
                    ULONG_PTR
                    >(
                        info.AllocationBase
                        );


                ULONG_PTR highest =
                    image_base;


                for (
                    PLIST_ENTRY scan =
                    memory_list->Flink;

                    scan !=
                    memory_list;

                    scan =
                    scan->Flink
                    )
                {
                    auto candidate =
                        CONTAINING_RECORD(
                            scan,

                            PROCESS_MEMORY_SNAPSHOT_ENTRY,

                            ListEntry
                        );


                    auto& candidate_info =
                        candidate->Information;


                    if (
                        !candidate_info.IsImage ||
                        candidate_info.AllocationBase !=
                        info.AllocationBase
                        )
                    {
                        continue;
                    }


                    const ULONG_PTR base =
                        reinterpret_cast<
                        ULONG_PTR
                        >(
                            candidate_info.BaseAddress
                            );


                    if (
                        candidate_info.RegionSize >
                        MAXULONG_PTR - base
                        )
                    {
                        continue;
                    }


                    const ULONG_PTR end =
                        base +
                        candidate_info.RegionSize;


                    if (
                        end >
                        highest
                        )
                    {
                        highest =
                            end;
                    }
                }


                if (
                    highest >=
                    image_base
                    )
                {
                    const SIZE_T span =
                        static_cast<SIZE_T>(
                            highest -
                            image_base
                            );


                    for (
                        PLIST_ENTRY scan =
                        memory_list->Flink;

                        scan !=
                        memory_list;

                        scan =
                        scan->Flink
                        )
                    {
                        auto candidate =
                            CONTAINING_RECORD(
                                scan,

                                PROCESS_MEMORY_SNAPSHOT_ENTRY,

                                ListEntry
                            );


                        auto& candidate_info =
                            candidate->Information;


                        if (
                            !candidate_info.IsImage ||
                            candidate_info.AllocationBase !=
                            info.AllocationBase
                            )
                        {
                            continue;
                        }


                        candidate_info.ImageSize =
                            span;
                    }
                }
            }
        }


        // ============================================================
        // Build TargetProcess Module Snapshot
        //
        // Native x64 loader list.
        //
        // UserMode never touches TargetProcess.
        // ============================================================

        inline NTSTATUS BuildModuleSnapshot(
            _In_ PEPROCESS target_process,

            _Out_ PLIST_ENTRY module_list
        )
        {
            if (
                target_process == nullptr ||
                module_list == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            InitializeListHead(
                module_list
            );


            PPEB peb =
                PsGetProcessPeb(
                    target_process
                );


            if (
                peb == nullptr
                )
            {
                return STATUS_NOT_FOUND;
            }


            KAPC_STATE apc_state{};


            KeStackAttachProcess(
                target_process,
                &apc_state
            );


            NTSTATUS status =
                STATUS_SUCCESS;


            __try
            {
                auto peb_view =
                    reinterpret_cast<
                    PHELPER_PEB_VIEW64
                    >(
                        peb
                        );


                if (
                    !IsUserRange(
                        peb_view,
                        sizeof(
                            HELPER_PEB_VIEW64
                            )
                    )
                    )
                {
                    status =
                        STATUS_ACCESS_VIOLATION;

                    __leave;
                }


                ProbeForRead(
                    peb_view,

                    sizeof(
                        HELPER_PEB_VIEW64
                        ),

                    sizeof(PVOID)
                );


                auto ldr =
                    peb_view->Ldr;


                if (
                    ldr == nullptr
                    )
                {
                    status =
                        STATUS_NOT_FOUND;

                    __leave;
                }


                if (
                    !IsUserRange(
                        ldr,
                        sizeof(
                            HELPER_PEB_LDR_DATA_VIEW64
                            )
                    )
                    )
                {
                    status =
                        STATUS_ACCESS_VIOLATION;

                    __leave;
                }


                ProbeForRead(
                    ldr,

                    sizeof(
                        HELPER_PEB_LDR_DATA_VIEW64
                        ),

                    sizeof(PVOID)
                );


                PLIST_ENTRY list_head =
                    &ldr->InMemoryOrderModuleList;


                PLIST_ENTRY current =
                    ldr
                    ->InMemoryOrderModuleList
                    .Flink;


                ULONG module_index =
                    0;


                while (
                    current != nullptr &&
                    current != list_head &&
                    module_index <
                    MAX_PROCESS_MODULE_COUNT
                    )
                {
                    if (
                        !IsUserRange(
                            current,
                            sizeof(
                                LIST_ENTRY
                                )
                        )
                        )
                    {
                        status =
                            STATUS_DATA_ERROR;

                        break;
                    }


                    ProbeForRead(
                        current,

                        sizeof(
                            LIST_ENTRY
                            ),

                        sizeof(PVOID)
                    );


                    auto loader_entry =
                        CONTAINING_RECORD(
                            current,

                            HELPER_LDR_DATA_TABLE_ENTRY_VIEW64,

                            InMemoryOrderLinks
                        );


                    if (
                        !IsUserRange(
                            loader_entry,
                            sizeof(
                                HELPER_LDR_DATA_TABLE_ENTRY_VIEW64
                                )
                        )
                        )
                    {
                        status =
                            STATUS_DATA_ERROR;

                        break;
                    }


                    ProbeForRead(
                        loader_entry,

                        sizeof(
                            HELPER_LDR_DATA_TABLE_ENTRY_VIEW64
                            ),

                        sizeof(PVOID)
                    );


                    const LIST_ENTRY links =
                        loader_entry
                        ->InMemoryOrderLinks;


                    const PVOID dll_base =
                        loader_entry->DllBase;


                    const UNICODE_STRING full_name =
                        loader_entry->FullDllName;


                    //
                    // Move current before allocating/copying.
                    //
                    current =
                        links.Flink;


                    if (
                        dll_base == nullptr
                        )
                    {
                        ++module_index;

                        continue;
                    }


                    auto module =
                        reinterpret_cast<
                        PPROCESS_MODULE_SNAPSHOT_ENTRY
                        >(
                            helper::allocate::kernelmode::
                            AllocateKernelMemory(
                                sizeof(
                                    PROCESS_MODULE_SNAPSHOT_ENTRY
                                    )
                            )
                            );


                    if (
                        module == nullptr
                        )
                    {
                        status =
                            STATUS_INSUFFICIENT_RESOURCES;

                        break;
                    }


                    RtlZeroMemory(
                        module,
                        sizeof(*module)
                    );


                    module->DllBase =
                        dll_base;


                    module->IsMainImage =
                        (
                            module_index == 0
                            );


                    //
                    // ------------------------------------------------
                    // Full path
                    // ------------------------------------------------
                    //

                    NTSTATUS string_status =
                        CopyTargetUnicodeString(
                            &full_name,

                            module->FullDllName,

                            MEMORY_IMAGE_PATH_LENGTH
                        );


                    if (
                        !NT_SUCCESS(
                            string_status
                        )
                        )
                    {
                        module
                            ->FullDllName[0] =
                            L'\0';
                    }


                    //
                    // ------------------------------------------------
                    // Base name
                    // ------------------------------------------------
                    //

                    ExtractBaseName(
                        module->FullDllName,

                        MEMORY_IMAGE_PATH_LENGTH,

                        module->BaseDllName,

                        MEMORY_IMAGE_NAME_LENGTH
                    );


                    //
                    // ------------------------------------------------
                    // PE Header
                    // ------------------------------------------------
                    //

                    SIZE_T image_size =
                        0;


                    ULONG timestamp =
                        0;


                    ULONG checksum =
                        0;


                    NTSTATUS pe_status =
                        QueryImagePeHeader(
                            dll_base,

                            &image_size,

                            &timestamp,

                            &checksum
                        );


                    if (
                        NT_SUCCESS(
                            pe_status
                        )
                        )
                    {
                        module
                            ->HasPeHeaderInformation =
                            TRUE;


                        module->SizeOfImage =
                            image_size;


                        module->TimeDateStamp =
                            timestamp;


                        module->CheckSum =
                            checksum;
                    }


                    InsertTailList(
                        module_list,
                        &module->ListEntry
                    );


                    ++module_index;
                }


                //
                // Hit safety limit.
                //
                if (
                    module_index >=
                    MAX_PROCESS_MODULE_COUNT &&
                    current != list_head
                    )
                {
                    status =
                        STATUS_BUFFER_OVERFLOW;
                }
            }
            __except (
                EXCEPTION_EXECUTE_HANDLER
                )
            {
                status =
                    GetExceptionCode();
            }


            KeUnstackDetachProcess(
                &apc_state
            );


            return status;
        }


        // ============================================================
        // Match memory areas to loader modules
        // ============================================================

        inline VOID EnrichMemorySnapshotWithModules(
            _Inout_ PLIST_ENTRY memory_list,

            _In_ PLIST_ENTRY module_list
        )
        {
            if (
                memory_list == nullptr ||
                module_list == nullptr
                )
            {
                return;
            }


            for (
                PLIST_ENTRY memory_entry =
                memory_list->Flink;

                memory_entry !=
                memory_list;

                memory_entry =
                memory_entry->Flink
                )
            {
                auto memory =
                    CONTAINING_RECORD(
                        memory_entry,

                        PROCESS_MEMORY_SNAPSHOT_ENTRY,

                        ListEntry
                    );


                auto& info =
                    memory->Information;


                if (
                    !info.IsImage ||
                    info.AllocationBase == nullptr
                    )
                {
                    continue;
                }


                for (
                    PLIST_ENTRY module_entry =
                    module_list->Flink;

                    module_entry !=
                    module_list;

                    module_entry =
                    module_entry->Flink
                    )
                {
                    auto module =
                        CONTAINING_RECORD(
                            module_entry,

                            PROCESS_MODULE_SNAPSHOT_ENTRY,

                            ListEntry
                        );


                    if (
                        module->DllBase !=
                        info.AllocationBase
                        )
                    {
                        continue;
                    }


                    //
                    // ------------------------------------------------
                    // Loader match
                    // ------------------------------------------------
                    //

                    info.HasImageInformation =
                        TRUE;


                    info.IsMainImage =
                        module->IsMainImage;


                    info.ImageBaseAddress =
                        module->DllBase;


                    //
                    // Prefer PE SizeOfImage.
                    //
                    if (
                        module->SizeOfImage != 0
                        )
                    {
                        info.ImageSize =
                            module->SizeOfImage;
                    }


                    info.HasPeHeaderInformation =
                        module
                        ->HasPeHeaderInformation;


                    info.ImageTimeDateStamp =
                        module->TimeDateStamp;


                    info.ImageCheckSum =
                        module->CheckSum;


                    info.IsImageBase =
                        (
                            info.BaseAddress ==
                            module->DllBase
                            );


                    const ULONG_PTR region_base =
                        reinterpret_cast<
                        ULONG_PTR
                        >(
                            info.BaseAddress
                            );


                    const ULONG_PTR image_base =
                        reinterpret_cast<
                        ULONG_PTR
                        >(
                            module->DllBase
                            );


                    if (
                        region_base >=
                        image_base
                        )
                    {
                        info.ImageRegionOffset =
                            static_cast<SIZE_T>(
                                region_base -
                                image_base
                                );
                    }


                    RtlCopyMemory(
                        info.ImageName,

                        module->BaseDllName,

                        sizeof(
                            info.ImageName
                            )
                    );


                    RtlCopyMemory(
                        info.ImagePath,

                        module->FullDllName,

                        sizeof(
                            info.ImagePath
                            )
                    );


                    break;
                }
            }
        }


        // ============================================================
        // MAIN
        //
        // ReadProcessInformation
        //
        // PHASE 1
        //     Target VA snapshot
        //
        // PHASE 2
        //     MEM_IMAGE fallback grouping
        //
        // PHASE 3
        //     Target PEB/Ldr module snapshot
        //
        // PHASE 4
        //     Match module -> memory regions
        //
        // PHASE 5
        //     Copy completed structures into requester UserMode list
        // ============================================================

        inline NTSTATUS ReadProcessInformation(
            _In_ HANDLE request_process_handle,

            _In_ HANDLE target_process_handle,

            _Out_ PVOID* output_first_node
        )
        {
            if (
                request_process_handle == nullptr ||
                target_process_handle == nullptr ||
                output_first_node == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            *output_first_node =
                nullptr;


            if (
                KeGetCurrentIrql() !=
                PASSIVE_LEVEL
                )
            {
                return STATUS_INVALID_DEVICE_STATE;
            }


            NTSTATUS status =
                STATUS_SUCCESS;


            LIST_ENTRY memory_list;

            LIST_ENTRY module_list;


            InitializeListHead(
                &memory_list
            );


            InitializeListHead(
                &module_list
            );


            PEPROCESS target_process =
                nullptr;


            //
            // ========================================================
            // Reference target EPROCESS
            // ========================================================
            //

            status =
                ObReferenceObjectByHandle(
                    target_process_handle,

                    PROCESS_QUERY_INFORMATION,

                    *PsProcessType,

                    KernelMode,

                    reinterpret_cast<PVOID*>(
                        &target_process
                        ),

                    nullptr
                );


            if (
                !NT_SUCCESS(status)
                )
            {
                return status;
            }


            //
            // ========================================================
            // PHASE 1
            //
            // Entire TargetProcess virtual-memory map
            // ========================================================
            //

            status =
                BuildMemorySnapshot(
                    target_process_handle,

                    &memory_list
                );


            if (
                !NT_SUCCESS(status)
                )
            {
                ObDereferenceObject(
                    target_process
                );


                FreeMemorySnapshot(
                    &memory_list
                );


                return status;
            }


            //
            // ========================================================
            // PHASE 2
            //
            // Build fallback ImageBase/ImageSize based on MEM_IMAGE
            // regions.
            // ========================================================
            //

            BuildFallbackImageSpans(
                &memory_list
            );


            //
            // ========================================================
            // PHASE 3
            //
            // PEB -> Ldr -> modules
            //
            // Module enumeration failure does NOT invalidate memory
            // map. We simply return regions without loader metadata.
            // ========================================================
            //

            NTSTATUS module_status =
                BuildModuleSnapshot(
                    target_process,

                    &module_list
                );


            if (
                NT_SUCCESS(
                    module_status
                ) ||
                module_status ==
                STATUS_BUFFER_OVERFLOW
                )
            {
                //
                // ====================================================
                // PHASE 4
                //
                // Module <-> MEM_IMAGE mapping
                // ====================================================
                //

                EnrichMemorySnapshotWithModules(
                    &memory_list,

                    &module_list
                );
            }


            //
            // Target EPROCESS no longer needed.
            //

            ObDereferenceObject(
                target_process
            );


            target_process =
                nullptr;


            //
            // ========================================================
            // PHASE 5
            //
            // Kernel snapshot -> requester UserMode linked list
            // ========================================================
            //

            helper::linkedlist::PLINKED_LIST_NODE first_node =nullptr;
            ULONG result_count = 0;


            helper::linkedlist::PLINKED_LIST_NODE latest_node =
                nullptr;


            for (
                PLIST_ENTRY current =
                memory_list.Flink;

                current !=
                &memory_list;

                current =
                current->Flink
                )
            {
                auto snapshot =
                    CONTAINING_RECORD(
                        current,

                        PROCESS_MEMORY_SNAPSHOT_ENTRY,

                        ListEntry
                    );


                if (result_count >= helper::linkedlist::MAX_USER_RESULT_NODES)
                {
                    status = STATUS_QUOTA_EXCEEDED;
                    break;
                }
                ++result_count;
                auto created_node =
                    helper::linkedlist::usermode::
                    InsertList(
                        request_process_handle,

                        latest_node,

                        reinterpret_cast<PUCHAR>(
                            &snapshot
                            ->Information
                            ),

                        sizeof(
                            READ_PROCESS_MEMORY_AREA_INFORMATION
                            )
                    );


                if (
                    created_node ==
                    nullptr
                    )
                {
                    status =
                        STATUS_INSUFFICIENT_RESOURCES;

                    break;
                }


                if (
                    first_node ==
                    nullptr
                    )
                {
                    first_node = reinterpret_cast<helper::linkedlist::PLINKED_LIST_NODE>(created_node);
                }


                latest_node = reinterpret_cast<helper::linkedlist::PLINKED_LIST_NODE>(created_node);
            }


            //
            // ========================================================
            // Temporary kernel structures cleanup
            // ========================================================
            //

            FreeModuleSnapshot(
                &module_list
            );


            FreeMemorySnapshot(
                &memory_list
            );


            //
            // ========================================================
            // Rollback partially-created UserMode list
            // ========================================================
            //

            if (
                !NT_SUCCESS(status)
                )
            {
                if (
                    first_node !=
                    nullptr
                    )
                {
                    helper::linkedlist::usermode::
                        FreeLinkedList(
                            request_process_handle,

                            first_node
                        );
                }


                return status;
            }


            //
            // ========================================================
            // Result
            // ========================================================
            //

            *output_first_node = first_node;


            return STATUS_SUCCESS;
        }

    }
}

    namespace ioctl
    {
        _Dispatch_type_(IRP_MJ_CREATE)
        _Dispatch_type_(IRP_MJ_CLOSE)
        inline DRIVER_DISPATCH DefaultCreateCloseRoutine;

        typedef _Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DEVICE_CONTROL_DISPATCH;
        typedef DEVICE_CONTROL_DISPATCH* PDEVICE_CONTROL_DISPATCH;

        inline NTSTATUS DefaultCreateCloseRoutine(
            _In_ PDEVICE_OBJECT device_object,
            _Inout_ PIRP irp
        )
        {
            UNREFERENCED_PARAMETER(device_object);

            if (irp == nullptr)
                return STATUS_INVALID_PARAMETER;

            irp->IoStatus.Status =
                STATUS_SUCCESS;

            irp->IoStatus.Information =
                0;

            IoCompleteRequest(
                irp,
                IO_NO_INCREMENT
            );

            return STATUS_SUCCESS;
        }


        inline NTSTATUS RegisterIoctlRoutine(
            _In_ PDRIVER_OBJECT driver_object,
            _In_ PCWSTR device_name,
            _In_ PCWSTR symbolic_link_name,
            _Out_opt_ PDEVICE_OBJECT* created_device_object = nullptr
        )
        {
            //
            // Device creation and symbolic-link creation
            // are PASSIVE_LEVEL operations.
            //
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return STATUS_INVALID_DEVICE_STATE;

            if (
                driver_object == nullptr ||
                device_name == nullptr ||
                symbolic_link_name == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            if (created_device_object != nullptr)
                *created_device_object = nullptr;


            UNICODE_STRING nt_device_name = {};
            UNICODE_STRING dos_device_name = {};


            RtlInitUnicodeString(
                &nt_device_name,
                device_name
            );

            RtlInitUnicodeString(
                &dos_device_name,
                symbolic_link_name
            );


            PDEVICE_OBJECT device_object =
                nullptr;


            //
            // ---------------------------------------------------------
            // Create named device object.
            //
            // Example:
            //
            //   \Device\MyDriver
            //
            // ---------------------------------------------------------
            //

            NTSTATUS status =
                IoCreateDevice(
                    driver_object,
                    0,
                    &nt_device_name,
                    FILE_DEVICE_UNKNOWN,
                    FILE_DEVICE_SECURE_OPEN,
                    FALSE,
                    &device_object
                );


            if (!NT_SUCCESS(status))
                return status;


            //
            // ---------------------------------------------------------
            // Configure device flags.
            //
            // METHOD_BUFFERED IOCTLs use SystemBuffer.
            // ---------------------------------------------------------
            //

            device_object->Flags |=
                DO_BUFFERED_IO;


            //
            // ---------------------------------------------------------
            // Create DOS symbolic link.
            //
            // Example:
            //
            //   \DosDevices\MyDriver
            //
            // UserMode:
            //
            //   \\.\MyDriver
            //
            // ---------------------------------------------------------
            //

            status =
                IoCreateSymbolicLink(
                    &dos_device_name,
                    &nt_device_name
                );


            if (!NT_SUCCESS(status))
            {
                IoDeleteDevice(
                    device_object
                );

                return status;
            }


            // Dispatch pointers are initialized by DriverEntry before this
            // device becomes visible to callers.
            device_object->Flags &= ~DO_DEVICE_INITIALIZING;
            if (created_device_object != nullptr)
                *created_device_object = device_object;
            return STATUS_SUCCESS;
        }


        inline VOID UnregisterIoctlRoutine(
            _In_opt_ PDEVICE_OBJECT device_object,
            _In_ PCWSTR symbolic_link_name
        )
        {
            if (symbolic_link_name == nullptr) return;
            UNICODE_STRING dos_device_name = {};
            RtlInitUnicodeString(&dos_device_name, symbolic_link_name);
            IoDeleteSymbolicLink(&dos_device_name);
            // Delete only the object returned by our successful IoCreateDevice.
            // No unsynchronized traversal of DRIVER_OBJECT/NextDevice lists.
            if (device_object != nullptr) IoDeleteDevice(device_object);
        }
    }

    namespace diagnostics
    {
        inline LARGE_INTEGER& DriverStartTime()
        {
            static LARGE_INTEGER s = {};
            return s;
        }

        inline volatile LONG64* TotalIoctlCount()
        {
            static volatile LONG64 c = 0;
            return &c;
        }

        inline VOID RecordDriverStart()
        {
            KeQuerySystemTime(&DriverStartTime());
        }

        inline VOID IncrementIoctlCount()
        {
            InterlockedIncrement64(TotalIoctlCount());
        }
    }

}

