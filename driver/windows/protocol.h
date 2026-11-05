/*
 * What procwatch and the driver say to each other. Shared by the driver and,
 * by hand, by src/response/driver.rs: keep both in step and raise the version.
 */
#pragma once

#define PW_PORT_NAME        L"\\ProcwatchPort"
#define PW_PROTOCOL_VERSION 1
#define PW_MAX_PATTERN      260
#define PW_MAX_RULES        128

/* What a rule guards. */
#define PW_ON_FILE     1   /* opening a file for writing or deleting */
#define PW_ON_REGISTRY 2   /* changing a key or value */

#define PW_MODE_AUDIT   0  /* report, allow */
#define PW_MODE_ENFORCE 1  /* report, deny */

#pragma pack(push, 1)
typedef struct _PW_RULE {
    unsigned long On;
    /* Case-insensitive, NUL-terminated; a trailing * matches any remainder.
     * Matched against NT paths: \Device\HarddiskVolume3\..., \REGISTRY\MACHINE\... */
    wchar_t Pattern[PW_MAX_PATTERN];
} PW_RULE;

/* Sent to the port. Replaces every rule at once; Count == 0 clears them. */
typedef struct _PW_SET_RULES {
    unsigned long Version;
    unsigned long Mode;
    unsigned long ProtectedPid; /* refuse to terminate this process; 0 = none */
    unsigned long Count;
    PW_RULE Rules[1];
} PW_SET_RULES;
#pragma pack(pop)
