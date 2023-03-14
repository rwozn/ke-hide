#pragma once

#include <ntifs.h>

typedef unsigned char BYTE;

#define PAD(COUNT) BYTE padding##COUNT[COUNT]

#pragma pack(push, 1)

#define THREAD_ALERTABLE_FLAG 32

typedef struct
{
	PAD(0x3C);

	// 0x3C
	// (we only need the Alertable bit)
	union
	{
		ULONG MiscFlags;
		/* Bit  0  */	  ULONG KernelStackResident: 1;
		/* Bit  1  */	  ULONG ReadyTransition: 1;
		/* Bit  2  */	  ULONG ProcessReadyQueue: 1;
		/* Bit  3  */	  ULONG WaitNext: 1;
		/* Bit  4  */	  ULONG SystemAffinityActive: 1;
		/* Bit  5  */	  ULONG Alertable: 1;
		/* Bit  6  */	  ULONG GdiFlushActive: 1;
		/* Bit  7  */	  ULONG UserStackWalkActive: 1;
		/* Bit  8  */	  ULONG ApcInterruptRequest: 1;
		/* Bit  9  */	  ULONG ForceDeferSchedule: 1;
		/* Bit  10 */	  ULONG QuantumEndMigrate: 1;
		/* Bit  11 */	  ULONG UmsDirectedSwitchEnable: 1;
		/* Bit  12 */	  ULONG TimerActive: 1;
		/* Bit  13 */	  ULONG SystemThread: 1;
		/* Bits 14-31 */  ULONG Reserved: 18;
	};

	// 0x40
	KAPC_STATE ApcState;

	PAD(0xF8);

	// 0x150
	EPROCESS* Process;

	PAD(0x114);

	// 0x268
	LIST_ENTRY ThreadListEntry; // size = 0x8

	PAD(0x10);

	// 0x280
	// (we only need ThreadIoPriority)
	union
	{
		ULONG CrossThreadFlags;
		/* Bit 0  */	  ULONG Terminated: 1;
		/* Bit 1  */      ULONG ThreadInserted: 1;
		/* Bit 2  */	  ULONG HideFromDebugger: 1;
		/* Bit 3  */	  ULONG ActiveImpersonationInfo: 1;
		/* Bit 4  */	  ULONG Reserved1: 1;
		/* Bit 5  */	  ULONG HardErrorsAreDisabled: 1;
		/* Bit 6  */	  ULONG BreakOnTermination: 1;
		/* Bit 7  */	  ULONG SkipCreationMsg: 1;
		/* Bit 8  */	  ULONG SkipTerminationMsg: 1;
		/* Bit 9  */	  ULONG CopyTokenOnOpen: 1;
		/* Bits 10-12 */ ULONG ThreadIoPriority: 3;
		/* Bits 13-15 */ ULONG ThreadPagePriority: 3;
		/* Bit 16 */	  ULONG RundownFail: 1;
		/* Bit 17 */	  ULONG NeedsWorkingSetAging: 1;
	};
} ETHREAD;

#pragma pack(pop)
