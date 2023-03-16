#pragma once

#include <wdm.h> // for InterlockedExchange

/*
	The Windows executive runs in kernel mode and provides native
	support to all of the operating system's subsystems: Win32, POSIX, and OS/2.
	These native system services' addresses are listed in a kernel structure
	called the System Service Dispatch Table (SSDT).

	A system service dispatch is triggered when an INT 2E or SYSENTER
	instruction is called. This causes a process to transition into kernel mode
	by calling the system service dispatcher. An application can call the system
	service dispatcher, KiSystemService, directly, or through the use of the subsystem.
	If the subsystem (such as Win32) is used, it calls into Ntdll.dll, which loads
	EAX with the system service identifier number or index of the system function
	requested. It then loads EDX with the address of the function parameters in
	user mode. The system service dispatcher verifies the number of parameters,
	and copies them from the user stack onto the kernel stack. It then calls
	the function stored at the address indexed in the SSDT by the service identifier
	number in EAX.
*/

#pragma pack(push, 1)

typedef struct
{
	unsigned int* systemServiceDescriptorTableBase;

	unsigned int* serviceCounterTableBase;

	unsigned int servicesAmount;

	// systemServiceParameterTable specifies number of bytes for
	// parameters for each system service
	unsigned char* systemServiceParameterTableBase;
} SystemServiceDescriptorTableEntry;

#pragma pack(pop)

// structure exported by Ntoskrnl.exe
// The KeServiceDescriptorTable is a table exported by the kernel.
// The table contains a pointer to the portion of the SSDT that
// contains the core system services implemented in Ntoskrnl.exe,
// which is a major piece of the kernel.
// The KeServiceDescriptorTable also contains a pointer to the SSPT.
NTSYSAPI
SystemServiceDescriptorTableEntry KeServiceDescriptorTable;

// This macro takes the address of a Zw* function and returns its corresponding index
// number in the SSDT
// This macro (and GET_NT_FUNCTION_FROM_ZW_FUNCTION) works because of the opcode
// at the beginning of the Zw* functions. As of this writing, all the Zw*
// functions in the kernel begin with the opcode mov eax, ULONG, where ULONG
// is the index number of the system call in the SSDT. By looking at the second
// byte of the function as a ULONG, these macros get the index number of the
// function
#define GET_NT_FUNCTION_SSDT_INDEX(ZW_FUNCTION)\
*(unsigned long*)((char*)ZW_FUNCTION + 1)

// Takes the address of a function exported by ntoskrnl.exe, a Zw* function,
// and returns the address of the corresponding Nt* function in the SSDT.
// The Nt* functions are the private functions whose addresses are contained
// in the SSDT. The Zw* functions are those exported by the kernel for the
// use of device drivers and other kernel components. Note that there is not
// a one-to-one correspondence between each entry in the SSDT and each Zw* function
#define GET_NT_FUNCTION_FROM_ZW_FUNCTION(ZW_FUNCTION)                                             \
KeServiceDescriptorTable.systemServiceDescriptorTableBase[GET_NT_FUNCTION_SSDT_INDEX(ZW_FUNCTION)]

// The InterlockedExchange routine sets an integer variable to a given value as an atomic operation.
// InterlockedExchange returns the value of the variable at Target (i.e. the first parameter) when the call occurred.
// So it returns the old value of the hooked Zw* function as Nt* function, i.e.:
// GET_NT_FUNCTION_FROM_ZW_FUNCTION(ZW_FUNCTION), thanks to which it can be restored later
// WRITABLE_SSDT is SSDT mapped by MDL, i.e. pointer returned by e.g. MmGetSystemAddressForMdlSafe
// because SSDT can be read-only by default
#define HOOK_NT_FUNCTION(ZW_FUNCTION, HOOK_FUNCTION, WRITABLE_SSDT)                        \
InterlockedExchange(&WRITABLE_SSDT[GET_NT_FUNCTION_SSDT_INDEX(ZW_FUNCTION)], HOOK_FUNCTION)

// returns address of the function that were the hook
#define UNHOOK_NT_FUNCTION(ZW_FUNCTION, ORIGINAL_NT_FUNCTION, WRITABLE_SSDT)                      \
InterlockedExchange(&WRITABLE_SSDT[GET_NT_FUNCTION_SSDT_INDEX(ZW_FUNCTION)], ORIGINAL_NT_FUNCTION)