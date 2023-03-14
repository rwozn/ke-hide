#pragma once

typedef struct
{
	unsigned short limit;

	unsigned short lowBase;

	unsigned short highBase;
} InterruptDescriptorTableInformation;

// Entry in the IDT, this is sometimes called an "interrupt gate"
// This data structure is used to locate the function in memory that will
// deal with an interrupt event. Using an interrupt gate, a user-mode program can call
// kernel-mode routines. For example, the interrupt for a system call
// is targeted at offset 0x2E in the IDT table
//
// Remember that the IDT can have up to 256 entries
// Each entry in the IDT contains a pointer to an interrupt service routine.
//
// The entries have the following structure:

#pragma pack(push, 1) // disable padding

typedef struct
{
	unsigned short lowWordOfInterruptServiceRoutineAddress;

	unsigned short selector;

	unsigned char unusedLo;

	unsigned char segmentType: 4; // 0xE is interrupt gate

	unsigned char systemSegmentFlag: 1;

	unsigned char descriptorPrivilegeLevel: 2;

	unsigned char present: 1;

	unsigned short highWordOfInterruptServiceRoutineAddress;
} InterruptDescriptorTableEntry;

#pragma pack(pop) // back to whatever the previous packing mode was (enable padding again)

// To access the IDT, use the MAKE_LONG function:
// The MAKE_LONG macro creates an unsigned 32-bit value
// by concatenating two given 16-bit values
// LOW_WORD - low-order word of long value
// HIGH_WORD - high-order word of long value
#define WORD unsigned short
#define DWORD unsigned long

#define MAKE_LONG(LOW_WORD, HIGH_WORD)                            \
((DWORD)(((WORD)(LOW_WORD)) | ((DWORD)((WORD)(HIGH_WORD))) << 16))

// The maximum number of entries in the IDT is 256
#define MAX_INTERRUPT_DESCRIPTOR_TABLE_ENTRIES 0xFF