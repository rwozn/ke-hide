#pragma once

#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000

#ifdef _WIN64
	#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG64
#else
	#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG32
#endif

typedef unsigned long DWORD;

typedef struct _IMAGE_THUNK_DATA32
{
	union
	{
		DWORD ForwarderString;      // PBYTE 
		DWORD Function;             // PDWORD
		DWORD Ordinal;
		DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA32;