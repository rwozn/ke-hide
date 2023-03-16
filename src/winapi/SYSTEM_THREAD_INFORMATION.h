#pragma once

#include <ntifs.h>

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER Reserved1[3];
	ULONG Reserved2;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG Reserved3;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION;