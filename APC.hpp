// TESTED on Windows 25h2

#pragma warning(disable: 4996)

#pragma once
#ifndef APC_HPP
#define APC_HPP

#include <ntifs.h>

// ──────────────────────────────────────────────────────────────
// 커널 함수 선언
// ──────────────────────────────────────────────────────────────

// KE

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

// 1. NormalRoutine — 반드시 먼저 선언
typedef VOID(NTAPI KNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
    );

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;


// 2. KernelRoutine
typedef VOID(NTAPI KKERNEL_ROUTINE)(
    PRKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
    );

typedef KKERNEL_ROUTINE* PKKERNEL_ROUTINE;


// 3. RundownRoutine
typedef VOID(NTAPI KRUNDOWN_ROUTINE)(
    PRKAPC Apc
    );

typedef KRUNDOWN_ROUTINE* PKRUNDOWN_ROUTINE;

extern "C" {

    NTKERNELAPI VOID KeInitializeApc(
        PRKAPC            Apc,
        PRKTHREAD         Thread,
        KAPC_ENVIRONMENT  Environment,
        PKKERNEL_ROUTINE  KernelRoutine,
        PKRUNDOWN_ROUTINE RundownRoutine,
        PKNORMAL_ROUTINE  NormalRoutine,
        KPROCESSOR_MODE   ApcMode,
        PVOID             NormalContext
    );

    NTKERNELAPI BOOLEAN KeInsertQueueApc(
        PRKAPC    Apc,
        PVOID     SystemArgument1,
        PVOID     SystemArgument2,
        KPRIORITY Increment
    );

    NTKERNELAPI
        BOOLEAN
        NTAPI
        KeTestAlertThread(
            _In_ KPROCESSOR_MODE Mode
        );

}

// ──────────────────────────────────────────────────────────────
// APC
// ──────────────────────────────────────────────────────────────

#define APC_POOL_TAG 'CPAK'

// ──────────────────────────────────────────────────────────────
// Kernel APC Routine
// ──────────────────────────────────────────────────────────────


extern "C" {

    static VOID ApcKernelRoutine(
        PRKAPC             Apc,
        PKNORMAL_ROUTINE* NormalRoutine,
        PVOID* NormalContext,
        PVOID* SystemArgument1,
        PVOID* SystemArgument2
    )
    {
        UNREFERENCED_PARAMETER(Apc);
        UNREFERENCED_PARAMETER(NormalRoutine);
        UNREFERENCED_PARAMETER(NormalContext);
        UNREFERENCED_PARAMETER(SystemArgument1);
        UNREFERENCED_PARAMETER(SystemArgument2);

        KeTestAlertThread(UserMode); // 이게 무조건 있어야 No Alertable 스레드 상태여도 NormalRoutine(프로세스 가상주소 공간 함수) 호출이 가능하다. (입증됨)


        ExFreePoolWithTag(Apc, APC_POOL_TAG);
    }

    // ──────────────────────────────────────────────────────────────
    // Rundown Routine — APC 미실행 채로 스레드 종료 시 호출
    // ──────────────────────────────────────────────────────────────

    static VOID ApcRundownRoutine(PRKAPC Apc)
    {
        UNREFERENCED_PARAMETER(Apc);
    }

}

// ──────────────────────────────────────────────────────────────
// 메인 함수
// ──────────────────────────────────────────────────────────────

NTSTATUS RegisterUserApc(
    _In_ HANDLE  ProcessId,
    _In_ HANDLE  ThreadId,
    _In_ PVOID   UserApcFunction,     // 유저모드 함수 주소
    _In_opt_ PVOID   NormalContext,
    _In_opt_ PVOID   NormalSystemParameter1,
    _In_opt_ PVOID   NormalSystemParameter2
)
{
    NTSTATUS    status = STATUS_SUCCESS;
    PEPROCESS   process = NULL;
    PETHREAD    thread = NULL;

    // ── 1. 인자 기본 검증 ──────────────────────────────────────

    if (!ProcessId || !ThreadId || !UserApcFunction) {
        return STATUS_INVALID_PARAMETER;
    }

    // 유저모드 주소 범위 확인 (커널 주소 거부)
    if ((ULONG_PTR)UserApcFunction >= (ULONG_PTR)MmUserProbeAddress) {
        return STATUS_ACCESS_VIOLATION;
    }

    // ── 2. ProcessId → PEPROCESS ──────────────────────────────

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 프로세스 종료 여부 확인
    if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
        status = STATUS_PROCESS_IS_TERMINATING;
        goto Cleanup;
    }

    // ── 3. ThreadId → PETHREAD ────────────────────────────────

    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 스레드가 해당 프로세스 소속인지 확인
    if (PsGetThreadProcess(thread) != process) {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // 스레드 종료 여부 확인
    if (PsIsThreadTerminating(thread)) {
        status = STATUS_THREAD_IS_TERMINATING;
        goto Cleanup;
    }

    // ── 4. APC 컨텍스트 할당 ──────────────────────────────────

    PRKAPC Kapc = (PRKAPC)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(KAPC),
        APC_POOL_TAG
    );
    if (!Kapc) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(Kapc, sizeof(KAPC));

    PRKAPC Uapc = (PRKAPC)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(KAPC),
        APC_POOL_TAG
    );
    if (!Uapc) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(Uapc, sizeof(KAPC));

    // ── 5. APC 초기화 ─────────────────────────────────────────

    // 유저용
    KeInitializeApc(
        Uapc,
        (PRKTHREAD)thread,
        OriginalApcEnvironment,
        ApcKernelRoutine,                       // Kernel routine
        ApcRundownRoutine,                       // Rundown routine
        (PKNORMAL_ROUTINE)UserApcFunction,       // ← 유저모드 함수 주소
        UserMode,                                // 커널모드는 Alertable no 상태에서  APC
        NormalContext                               // NormalContext (필요시 전달)
    );


    // 커널용
    KeInitializeApc(
        Kapc,
        (PRKTHREAD)thread,
        OriginalApcEnvironment,
        ApcKernelRoutine,                       // Kernel routine
        ApcRundownRoutine,                       // Rundown routine
        NULL,       // ← 유저모드 함수 주소
        KernelMode,                                // 커널모드는 Alertable no 상태에서  APC
        NULL                                     // NormalContext (필요시 전달)
    );

    // ── 7. APC 큐 삽입 ────────────────────────────────────────

    if (!KeInsertQueueApc(Uapc, NormalSystemParameter1, NormalSystemParameter2, IO_NO_INCREMENT)) {
        // 삽입 실패 = 스레드가 이미 종료 중이거나 APC 불가 상태
        status = STATUS_UNSUCCESSFUL;
        ExFreePoolWithTag(Uapc, APC_POOL_TAG);
        Uapc = NULL;
        goto Cleanup;
    }

    if (!KeInsertQueueApc(Kapc, NULL, NULL, IO_NO_INCREMENT)) {
        // 삽입 실패 = 스레드가 이미 종료 중이거나 APC 불가 상태
        status = STATUS_UNSUCCESSFUL;
        ExFreePoolWithTag(Kapc, APC_POOL_TAG);
        Kapc = NULL;
        goto Cleanup;
    }


    // 삽입 성공 시 ctx 소유권은 APC 런타임으로 이전
    // → Rundown 또는 KernelRoutine에서 해제됨
    // → 여기서 명시적 해제 금지

    ObDereferenceObject(thread);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;

Cleanup:
    if (thread)  ObDereferenceObject(thread);
    if (process) ObDereferenceObject(process);
    return status;
}

#endif