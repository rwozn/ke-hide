#pragma once

#include <ntifs.h>

typedef struct _HANDLE_TRACE_DB_ENTRY
{
	CLIENT_ID ClientId;
	PVOID Handle;
	ULONG Type;
	VOID* StackTrace[16];
} HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;

typedef struct _HANDLE_TRACE_DEBUG_INFO
{
	LONG RefCount;
	ULONG TableSize;
	ULONG BitMaskFlags;
	FAST_MUTEX CloseCompactionLock;
	ULONG CurrentStackIndex;
	HANDLE_TRACE_DB_ENTRY TraceDb[1];
} HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;

typedef unsigned char BYTE;

typedef struct
{
	ULONG Attributes;
	PVOID RootDirectory;
	BYTE ProbeMode;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	PVOID SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION;

typedef struct
{
	ULONG PointerCount;

	union
	{
		ULONG HandleCount;
		PVOID NextToFree;
	};

	EX_PUSH_LOCK Lock;
	BYTE TypeIndex;
	BYTE TraceFlags;
	BYTE InfoMask;
	BYTE Flags;

	union
	{
		OBJECT_CREATE_INFORMATION* ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};

	PVOID SecurityDescriptor;
	QUAD Body;
} OBJECT_HEADER;

typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		// Object having type OBJECT_HEADER* is my assumption,
		// in WinDbg it's PVOID, but taking a look at function
		// ObReferenceObjectByHandle e.g. here:
		/*
		HANDLE_TABLE_ENTRY = ExMapHandleToPointerEx(vPHANDLE_TABLE_ObjectTable, HANDLE, KPROCESSOR_MODE);
		if(HANDLE_TABLE_ENTRY)
		{
			OBJECT = *HANDLE_TABLE_ENTRY & 0xFFFFFFF8;
			TypeIndex = *(BYTE*)(OBJECT + 0xC);
			vOBJECT = *HANDLE_TABLE_ENTRY & 0xFFFFFFF8;
			if((OBJECT_TYPE*)*(&BugCheckParameter1 + TypeIndex) != POBJECT_TYPE && POBJECT_TYPE)
			{
				result_ = 0xC0000024;
			}
		*/
		// then the fact that e.g. TypeIndex is of type BYTE and using it it makes a comparison
		// with some POBJECT_TYPE makes it seem highly likely
		//
		// when Object is used in ObReferenceObjectByHandle it's done like so:
		// PVOID Object = *HandleTableEntry & 0xFFFFFFF8;
		// so I have to do it like so too (0xFFFFFFF8 in binary looks like:
		// 1111 1111 1111 1111 1111 1111 1111 1000 so & 0xFFFFFFF8 just
		// clears the first 3 bits; there's most likely something like RefCount)
		//
		// ObReferenceObjectByHandle then returns Object + 0x18 so Object->QUAD
		// considering the fact that QUAD is used to align (winddk says so in a comment)
		// and after some wininternals reading I can say that
		// after the OBJECT_HEADER, that's common for (I think) all objects,
		// there's, depending on the object, object_body, e.g.:
		// for process: [OBJECT_HEADER][EPROCESS]
		// for thread:  [OBJECT_HEADER][ETHREAD]
		// for field:   [OBJECT_HEADER][FILE_OBJECT]
		// also the field of type QUAD is called Body
		OBJECT_HEADER* Object; 
		ULONG ObAttributes;
		PHANDLE_TABLE_ENTRY_INFO InfoTable;
		ULONG Value;
	};
	union
	{
		ULONG GrantedAccess;
		struct
		{
			USHORT GrantedAccessIndex;
			USHORT CreatorBackTraceIndex;
		};
		LONG NextFreeTableEntry;
	};
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
	ULONG TableCode;
	PEPROCESS QuotaProcess;
	PVOID UniqueProcessId;
	EX_PUSH_LOCK HandleLock;
	// LIST_ENTRY of HANDLE_TABLEs of different processes
	// e.g. if current process is SYSTEM and we have its HANDLE_TABLE table; then:
	// table->Blink belongs to a different process
	// table->Flink belongs to a different process
	// while there exists a global kernal variable that contains
	// System process HANDLE_TABLE address. Flink of this HANDLE_TABLE
	// is most likely the head
	LIST_ENTRY HandleTableList;
	EX_PUSH_LOCK HandleContentionEvent;
	PHANDLE_TRACE_DEBUG_INFO DebugInfo;
	LONG ExtraInfoPages;
	ULONG Flags;
	ULONG StrictFIFO: 1;
	LONG FirstFreeHandle;
	PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
	LONG HandleCount;
	ULONG NextHandleNeedingPool;
	ULONG HandleCountHighWatermark;
} HANDLE_TABLE, *PHANDLE_TABLE;
