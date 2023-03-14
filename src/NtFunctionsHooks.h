#pragma once

#include <ntifs.h>
#include <wdm.h>

#define CLIENT_PROGRAM_NAME L"Client.exe"

#define CLIENT_PROGRAM_DIRECTORY_PATH L"C:\\"

#define CLIENT_PROGRAM_PATH CLIENT_PROGRAM_DIRECTORY_PATH CLIENT_PROGRAM_NAME

typedef unsigned char BYTE;

typedef enum
{
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, VOID* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);

NTSYSAPI
NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, VOID* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateFile(
PHANDLE FileHandle,
ACCESS_MASK DesiredAccess,
POBJECT_ATTRIBUTES ObjectAttributes,
PIO_STATUS_BLOCK IoStatusBlock,
PLARGE_INTEGER AllocationSize,
ULONG FileAttributes,
ULONG ShareAccess,
ULONG CreateDisposition,
ULONG CreateOptions,
PVOID EaBuffer,
ULONG EaLength
);

NTSTATUS
NTAPI
ntCreateFileHook(
PHANDLE FileHandle,
ACCESS_MASK DesiredAccess,
POBJECT_ATTRIBUTES ObjectAttributes,
PIO_STATUS_BLOCK IoStatusBlock,
PLARGE_INTEGER AllocationSize,
ULONG FileAttributes,
ULONG ShareAccess,
ULONG CreateDisposition,
ULONG CreateOptions,
PVOID EaBuffer,
ULONG EaLength
);
NTSTATUS NTAPI ntWriteFileHook(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);

NTSTATUS NTAPI ntQuerySystemInformationHook(SYSTEM_INFORMATION_CLASS SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);

NTSTATUS NTAPI ntOpenProcessHook(HANDLE* ProcessHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId);
