/*
 * procwatch.sys: a file-system minifilter and registry callback that denies
 * the operations a policy names. See README.md: THIS HAS NEVER BEEN LOADED.
 *
 * Rules of the design:
 * - Fail open. With no client connected, no rules, or any error in here, the
 *   operation proceeds. A filter that fails closed can stop a machine booting.
 * - Rules live only in memory and vanish when the client disconnects, the same
 *   promise --enforce makes: nothing outlives procwatch.
 * - Kernel-mode requests and the system process are never denied.
 * - Decisions take a shared lock and do no allocation beyond FltMgr's name
 *   lookup, at PASSIVE_LEVEL only.
 */
#include <fltKernel.h>
#include <ntstrsafe.h>
#include "protocol.h"

#define PW_TAG 'wcrP'

static PFLT_FILTER gFilter;
static PFLT_PORT gServerPort;
static PFLT_PORT gClientPort;
static LARGE_INTEGER gRegCookie;
static EX_PUSH_LOCK gLock;

/* Guarded by gLock. */
static PW_RULE *gRules;
static ULONG gRuleCount;
static ULONG gMode;

static BOOLEAN Matches(_In_ PCWSTR pattern, _In_ PCUNICODE_STRING text)
{
    USHORT length = text->Length / sizeof(WCHAR);
    USHORT i;

    for (i = 0; i < PW_MAX_PATTERN && pattern[i] != L'\0'; i++) {
        if (pattern[i] == L'*' && pattern[i + 1] == L'\0') {
            return TRUE;
        }
        if (i >= length || RtlUpcaseUnicodeChar(pattern[i]) != RtlUpcaseUnicodeChar(text->Buffer[i])) {
            return FALSE;
        }
    }
    return i == length;
}

/* TRUE to deny. Every path that isn't a definite match allows. */
static BOOLEAN Decide(_In_ ULONG on, _In_ PCUNICODE_STRING path)
{
    BOOLEAN deny = FALSE;
    ULONG i;

    if (PsGetCurrentProcess() == PsInitialSystemProcess) {
        return FALSE;
    }
    FltAcquirePushLockShared(&gLock);
    for (i = 0; i < gRuleCount; i++) {
        if (gRules[i].On == on && Matches(gRules[i].Pattern, path)) {
            deny = (gMode == PW_MODE_ENFORCE);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "procwatch: %s %wZ by %lu\n",
                       deny ? "denied" : "would deny", path, HandleToULong(PsGetCurrentProcessId()));
            break;
        }
    }
    FltReleasePushLock(&gLock);
    return deny;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI
PreCreate(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS objects, _Flt_CompletionContext_Outptr_ PVOID *context)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    ACCESS_MASK access;
    ULONG options;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(objects);
    *context = NULL;

    if (gRuleCount == 0 || data->RequestorMode == KernelMode || FLT_IS_FS_FILTER_OPERATION(data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    access = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    options = data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    if (!(access & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER)) &&
        !(options & FILE_DELETE_ON_CLOSE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Decide(PW_ON_FILE, &name->Name)) {
        FltReleaseFileNameInformation(name);
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    FltReleaseFileNameInformation(name);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS RegistryCallback(_In_ PVOID context, _In_opt_ PVOID arg1, _In_opt_ PVOID arg2)
{
    REG_NOTIFY_CLASS op = (REG_NOTIFY_CLASS)(ULONG_PTR)arg1;
    PVOID object = NULL;
    PCUNICODE_STRING name = NULL;
    NTSTATUS result = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(context);

    if (arg2 == NULL || gRuleCount == 0 || ExGetPreviousMode() == KernelMode || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_SUCCESS;
    }
    switch (op) {
    case RegNtPreSetValueKey:
        object = ((PREG_SET_VALUE_KEY_INFORMATION)arg2)->Object;
        break;
    case RegNtPreDeleteValueKey:
        object = ((PREG_DELETE_VALUE_KEY_INFORMATION)arg2)->Object;
        break;
    case RegNtPreDeleteKey:
        object = ((PREG_DELETE_KEY_INFORMATION)arg2)->Object;
        break;
    case RegNtPreRenameKey:
        object = ((PREG_RENAME_KEY_INFORMATION)arg2)->Object;
        break;
    default:
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&gRegCookie, object, NULL, &name, 0))) {
        return STATUS_SUCCESS;
    }
    if (Decide(PW_ON_REGISTRY, name)) {
        result = STATUS_ACCESS_DENIED;
    }
    CmCallbackReleaseKeyObjectIDEx(name);
    return result;
}

static VOID ClearRules(VOID)
{
    PW_RULE *old;

    FltAcquirePushLockExclusive(&gLock);
    old = gRules;
    gRules = NULL;
    gRuleCount = 0;
    gMode = PW_MODE_AUDIT;
    FltReleasePushLock(&gLock);
    if (old != NULL) {
        ExFreePoolWithTag(old, PW_TAG);
    }
}

static NTSTATUS FLTAPI
PortMessage(_In_opt_ PVOID cookie, _In_reads_bytes_opt_(inLength) PVOID in, _In_ ULONG inLength,
            _Out_writes_bytes_to_opt_(outLength, *returned) PVOID out, _In_ ULONG outLength, _Out_ PULONG returned)
{
    PW_SET_RULES header;
    PW_RULE *rules = NULL;
    PW_RULE *old;
    SIZE_T bytes;
    ULONG i;

    UNREFERENCED_PARAMETER(cookie);
    UNREFERENCED_PARAMETER(out);
    UNREFERENCED_PARAMETER(outLength);
    *returned = 0;

    if (in == NULL || inLength < FIELD_OFFSET(PW_SET_RULES, Rules)) {
        return STATUS_INVALID_PARAMETER;
    }
    /* The buffer belongs to user mode: copy once, then trust only the copy. */
    __try {
        ProbeForRead(in, inLength, 1);
        RtlCopyMemory(&header, in, FIELD_OFFSET(PW_SET_RULES, Rules));
        if (header.Version != PW_PROTOCOL_VERSION || header.Count > PW_MAX_RULES || header.Mode > PW_MODE_ENFORCE) {
            return STATUS_INVALID_PARAMETER;
        }
        bytes = (SIZE_T)header.Count * sizeof(PW_RULE);
        if (inLength < FIELD_OFFSET(PW_SET_RULES, Rules) + bytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (header.Count > 0) {
            rules = (PW_RULE *)ExAllocatePool2(POOL_FLAG_PAGED, bytes, PW_TAG);
            if (rules == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(rules, ((PW_SET_RULES *)in)->Rules, bytes);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (rules != NULL) {
            ExFreePoolWithTag(rules, PW_TAG);
        }
        return GetExceptionCode();
    }
    for (i = 0; i < header.Count; i++) {
        rules[i].Pattern[PW_MAX_PATTERN - 1] = L'\0';
    }
    FltAcquirePushLockExclusive(&gLock);
    old = gRules;
    gRules = rules;
    gRuleCount = header.Count;
    gMode = header.Mode;
    FltReleasePushLock(&gLock);
    if (old != NULL) {
        ExFreePoolWithTag(old, PW_TAG);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS FLTAPI PortConnect(_In_ PFLT_PORT client, _In_opt_ PVOID server, _In_reads_bytes_opt_(size) PVOID context,
                                   _In_ ULONG size, _Outptr_result_maybenull_ PVOID *cookie)
{
    UNREFERENCED_PARAMETER(server);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(size);
    *cookie = NULL;
    gClientPort = client;
    return STATUS_SUCCESS;
}

static VOID FLTAPI PortDisconnect(_In_opt_ PVOID cookie)
{
    UNREFERENCED_PARAMETER(cookie);
    /* Nothing outlives the client. */
    ClearRules();
    FltCloseClientPort(gFilter, &gClientPort);
}

static NTSTATUS OpenPort(VOID)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name = RTL_CONSTANT_STRING(PW_PORT_NAME);
    NTSTATUS status;

    /* FLT_PORT_ALL_ACCESS for administrators and SYSTEM only. */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
    status = FltCreateCommunicationPort(gFilter, &gServerPort, &attributes, NULL, PortConnect, PortDisconnect, PortMessage, 1);
    FltFreeSecurityDescriptor(sd);
    return status;
}

static NTSTATUS FLTAPI Unload(_In_ FLT_FILTER_UNLOAD_FLAGS flags)
{
    /* Refuse a casual `fltmc unload` while a client depends on it. */
    if (!(flags & FLTFL_FILTER_UNLOAD_MANDATORY) && gClientPort != NULL) {
        return STATUS_FLT_DO_NOT_DETACH;
    }
    CmUnRegisterCallback(gRegCookie);
    FltCloseCommunicationPort(gServerPort);
    FltUnregisterFilter(gFilter);
    ClearRules();
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    Unload,
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING registryPath)
{
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"370030");
    NTSTATUS status;

    UNREFERENCED_PARAMETER(registryPath);
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    FltInitializePushLock(&gLock);

    status = FltRegisterFilter(driver, &Registration, &gFilter);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = OpenPort();
    if (NT_SUCCESS(status)) {
        status = CmRegisterCallbackEx(RegistryCallback, &altitude, driver, NULL, &gRegCookie, NULL);
        if (!NT_SUCCESS(status)) {
            FltCloseCommunicationPort(gServerPort);
        }
    }
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(gFilter);
        if (!NT_SUCCESS(status)) {
            CmUnRegisterCallback(gRegCookie);
            FltCloseCommunicationPort(gServerPort);
        }
    }
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
    }
    return status;
}
