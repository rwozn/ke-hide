#pragma once

#include "HANDLE_TABLE.h"

typedef struct
{
	OBJECT_NAME_INFORMATION* ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO;

typedef unsigned char BYTE;

#define PAD(COUNT, SUFFIX) BYTE padding##COUNT##_##SUFFIX[COUNT]

typedef struct
{
	PAD(0xC);

	// 0xC
	LIST_ENTRY InLoadOrderModuleList; // LIST_ENTRY for LDR_DATA_TABLE_ENTRY
	
	// 0x14
	LIST_ENTRY InMemoryOrderModuleList;

	// 0x1C
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct
{
	PAD(0x8);

	//0x8
	void* ImageBaseAddress;

	//0xC
	PEB_LDR_DATA* Ldr;
} PEB;

typedef union
{
	ULONG Value;
	
	void* Object;
	
	ULONG RefCnt: 3;
} EX_FAST_REF; // size == sizeof(void*)

typedef union
{
	/* Bit 0 */ BYTE ExecuteDisable: 1;
	/* Bit 1 */ BYTE ExecuteEnable: 1;
	/* Bit 2 */ BYTE DisableThunkEmulation: 1;
	/* Bit 3 */ BYTE Permanent: 1;
	/* Bit 4 */ BYTE ExecuteDispatchEnable: 1;
	/* Bit 5 */ BYTE ImageDispatchEnable: 1;
	/* Bit 6 */ BYTE DisableExceptionChainValidation: 1;
	/* Bit 7 */ BYTE Spare: 1;
	
	BYTE ExecuteOptions;
} KEXECUTE_OPTIONS;

#pragma pack(push, 1)

// ThreadListHead is in KPROCESS and EPROCESS
// in KPROCESS there's ProcessListEntry and in EPROCESS others, ex. ActiveProcessLinks and MmProcessLinks
typedef struct
{
	PAD(0x6C);

	// 0x6C
	// it's Flags from KPROCESS, not from EPROCESS (in EPROCESS there's also a field named Flags)
	// can be gathered by KeGetExecuteOptions
	// used e.g. by GetProcessDEPPolicy -> NtQueryInformationProcess (ProcessInformationClass == 0x22) -> KeGetExecuteOptions
	// which returns whether DEP (Data Execution Prevention) is turned on; it's needed when creating a process
	// because addresses mapped by MDL can cause access violation - executing non-executable memory
	// and when DEP is turned off it's not a problem anymore
	//
	// if ExecuteEnable is set to 1 then executing data is allowed in the process
	KEXECUTE_OPTIONS Flags;

	PAD(0xB);

	// 0x78
	LIST_ENTRY ProcessListEntry;

	PAD(0x34);

	// 0xB4
	HANDLE UniqueProcessId; // size = 0x4

	// 0xB8
	LIST_ENTRY ActiveProcessLinks; // size = 0x8

	PAD(0x24);

	// 0xE4
	LIST_ENTRY SessionProcessLinks;

	PAD(0x8);

	// 0xF4
	PHANDLE_TABLE ObjectTable;

	// 0xF8
	EX_FAST_REF Token;

	PAD(0x8C);

	// 0x188
	LIST_ENTRY ThreadListHead; // size = 0x8

	PAD(0x8, 2);

	// 0x198
	// NT version 5.1 to 5.2     =>          ULONG ActiveThreads;
	// NT version 6.0 and higher => volatile ULONG ActiveThreads;
	volatile ULONG ActiveThreads; // size = 0x4

	PAD(0xC, 2);
	
	// 0x1A8
	PEB* Peb; // size = 0x4

	PAD(0x40);

	// 0x1EC
	SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo; // size = 0x4

	PAD(0x6C, 2);

	// 0x25C
	LIST_ENTRY MmProcessLinks;

	PAD(0x8, 3);

	// 0x26C
	union
	{
		// if ProtectedProcess is set to 1 (in client process)
		// then the process hangs for a moment and then terminates.
		// probably because something else checks if its signature is trusted
		// and if turns out it's not it's killed
		ULONG Flags2;
		/* Bit  0  */    ULONG JobNotReallyActive: 1;
		/* Bit  1  */    ULONG AccountingFolded: 1;
		/* Bit  2  */    ULONG NewProcessReported: 1;
		/* Bit  3  */    ULONG ExitProcessReported: 1;
		/* Bit  4  */    ULONG ReportCommitChanges: 1;
		/* Bit  5  */    ULONG LastReportMemory: 1;
		/* Bit  6  */    ULONG ReportPhysicalPageChanges: 1;
		/* Bit  7  */    ULONG HandleTableRundown: 1;
		/* Bit  8  */    ULONG NeedsHandleRundown: 1;
		/* Bit  9  */    ULONG RefTraceEnabled: 1;
		/* Bit  10 */    ULONG NumaAware: 1;
		/* Bit  11 */    ULONG ProtectedProcess: 1;
		/* Bits 12-14 */ ULONG DefaultPagePriority: 3;
		/* Bit  15 */	  ULONG PrimaryTokenFrozen: 1;
		/* Bit  16 */    ULONG ProcessVerifierTarget: 1;
		/* Bit  17 */    ULONG StackRandomizationDisabled: 1;
		/* Bit  18 */    ULONG AffinityPermanent: 1;
		/* Bit  19 */    ULONG AffinityUpdateEnable: 1;
		/* Bit  20 */    ULONG PropagateNode: 1;
		/* Bit  21 */    ULONG ExplicitAffinity: 1;
		/* Bit  22 */    ULONG Spare1: 1;
		/* Bit  23 */    ULONG ForceRelocateImages: 1;
		/* Bit  24 */    ULONG DisallowStrippedImages: 1;
		/* Bit  25 */    ULONG LowVaAccessible: 1;
		/* Bit  26 */    ULONG RestrictIndirectBranchPrediction: 1;
		/* Bit  27 */    ULONG AddressPolicyFrozen: 1;
		/* Bit  28 */    ULONG MemoryDisambiguationDisable: 1;
	};
} EPROCESS;

#pragma pack(pop)

void getProcessImageFileName(EPROCESS* process, UNICODE_STRING* imageFileName);