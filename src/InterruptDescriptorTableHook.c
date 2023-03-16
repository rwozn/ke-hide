#include "InterruptDescriptorTable.h"

#include <wdm.h>

#define LOWORD(VALUE) ((WORD)((DWORD)(VALUE) & 0xFFFF))
#define HIWORD(VALUE) ((WORD)((DWORD)(VALUE) >> 16))

void* hookInterruptServiceRoutine(DWORD interruptIndex, void* hookFunction)
{
	// this structure is obtained by calling STORE IDT (sidt)
	InterruptDescriptorTableInformation interruptDescriptorTableInformation;

	// load idtInformation
	__asm sidt interruptDescriptorTableInformation

	InterruptDescriptorTableEntry* interruptDescriptorTableEntries = (InterruptDescriptorTableEntry*)MAKE_LONG(interruptDescriptorTableInformation.lowBase, interruptDescriptorTableInformation.highBase);

	InterruptDescriptorTableEntry* interruptDescriptorTableEntry = &interruptDescriptorTableEntries[interruptIndex];

	void* originalInterruptServiceRoutine = MAKE_LONG(interruptDescriptorTableEntry->lowWordOfInterruptServiceRoutineAddress, interruptDescriptorTableEntry->highWordOfInterruptServiceRoutineAddress);

	DbgPrint(
				"Hooking ISR = 0x%X [index = %d]\n"
				"Hook function = 0x%X\n\n", originalInterruptServiceRoutine, interruptIndex, hookFunction);

	__asm cli; mask interrupts

	interruptDescriptorTableEntry->lowWordOfInterruptServiceRoutineAddress = LOWORD(hookFunction);
	interruptDescriptorTableEntry->highWordOfInterruptServiceRoutineAddress = HIWORD(hookFunction);

	__asm sti; enable interrupts again

	return originalInterruptServiceRoutine;
}

void* unhookInterruptServiceRoutine(unsigned long interruptIndex, void* originalInterruptServiceRoutine)
{
	InterruptDescriptorTableInformation interruptDescriptorTableInformation;

	// load idtInformation
	__asm sidt interruptDescriptorTableInformation

	InterruptDescriptorTableEntry* interruptDescriptorTableEntries = (InterruptDescriptorTableEntry*)MAKE_LONG(interruptDescriptorTableInformation.lowBase, interruptDescriptorTableInformation.highBase);

	InterruptDescriptorTableEntry* interruptDescriptorTableEntry = &interruptDescriptorTableEntries[interruptIndex];

	void* hookFunction = MAKE_LONG(interruptDescriptorTableEntry->lowWordOfInterruptServiceRoutineAddress, interruptDescriptorTableEntry->highWordOfInterruptServiceRoutineAddress);

	DbgPrint(
				"Unhooking ISR = 0x%X [index = %d]\n"
				"Hook function was = 0x % X\n\n", originalInterruptServiceRoutine, interruptIndex, hookFunction);

	__asm cli; mask interrupts

	interruptDescriptorTableEntry->lowWordOfInterruptServiceRoutineAddress = LOWORD(originalInterruptServiceRoutine);
	interruptDescriptorTableEntry->highWordOfInterruptServiceRoutineAddress = HIWORD(originalInterruptServiceRoutine);

	__asm sti; enable interrupts again

	return hookFunction;
}