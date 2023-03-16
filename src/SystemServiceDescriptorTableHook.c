#include "SystemServiceDescriptorTableHook.h"
#include "SystemServiceDescriptorTableEntry.h"

/*
	Some versions of Windows come with write protection enabled for certain portions of memory.
	This becomes more common with later versions, such as Windows XP and Windows 2003.
	These later versions of the operating system make the SSDT read-only because it is unlikely
	that any legitimate program would need to modify this table.

	You can describe a region of memory in a Memory Descriptor List (MDL).
	MDLs contain the start address, owning process, number of bytes, and flags for the memory region.

	To change the flags on the memory, the code below starts by declaring a structure used to cast the
	KeServiceDescriptorTable variable exported by the Windows kernel. You need the KeServiceDescriptorTable
	base and the number of entries it contains when you call MmCreateMdl. This defines the beginning and the
	size of the memory region you want the MDL to describe. We then build the MDL from the non-paged
	pool of memory. We change the flags on the MDL to allow us to write to a memory region by ORing
	them with the aforementioned MDL_MAPPED_TO_SYSTEM_VA. Next, we lock the MDL pages in memory by calling MmMapLockedPages.
*/

MDL* systemServiceDescriptorTableMdl = NULL;
void** writableSystemServiceDescriptorTable = NULL;

BOOLEAN initializeWritableSystemServiceDescriptorTable()
{
	// MmCreateMdl is obsolete and IoAllocateMdl should be used
	// The IoAllocateMdl routine allocates a memory descriptor list (MDL) large enough to map a buffer,
	// given the buffer's starting address and length.
	systemServiceDescriptorTableMdl = IoAllocateMdl(KeServiceDescriptorTable.systemServiceDescriptorTableBase, KeServiceDescriptorTable.servicesAmount * sizeof(void*), FALSE, FALSE, NULL);

	if(!systemServiceDescriptorTableMdl)
	{
		DbgPrint("IoAllocateMdl failed\n");

		return FALSE;
	}

	// The driver should call MmBuildMdlForNonPagedPool with the MDL
	// allocated by this call (i.e. call to IoAllocateMdl) to set up
	// an MDL describing a driver-allocated buffer in nonpaged pool.

	// The MmProbeAndLockPages routine probes the specified virtual memory pages,
	// makes them resident, and locks them in memory.
	// Calls to MmProbeAndLockPages must be enclosed in a try/except block.
	// If the pages do not support the specified operation, the routine raises the
	// STATUS_ACCESS_VIOLATION or other exceptions.
	__try
	{
		MmProbeAndLockPages(systemServiceDescriptorTableMdl, KernelMode, IoWriteAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("MmProbeAndLockPages failed with code %d\n", GetExceptionCode());

		IoFreeMdl(systemServiceDescriptorTableMdl);

		return FALSE;
	}

	// The MmMapLockedPages routine is obsolete for Windows 2000 and later versions of Windows,
	// and for Windows Me. It is supported only for WDM drivers that must run on Windows 98.
	// Otherwise, use MmMapLockedPagesSpecifyCache.

	// The MmMapLockedPagesSpecifyCache routine maps the physical pages that are
	// described by an MDL to a virtual address, and enables the caller to
	// specify the cache attribute that is used to create the mapping.
	// (MmGetSystemAddressForMdlSafe wywo³uje MmMapLockedPagesSpecifyCache)

	// To create a new system-address-space mapping, MmGetSystemAddressForMdlSafe calls MmMapLockedPagesSpecifyCache
	/*
		When the system-address-space mapping that is returned by MmGetSystemAddressForMdlSafe is no longer needed, it must be released.
		The steps that are required to release the mapping depend on how the MDL was built. These are the four possible cases:

		1. If the MDL was built by a call to the MmProbeAndLockPages routine, it is not necessary to explicitly release the system-address-space mapping.
		Instead, a call to the MmUnlockPages routine releases the mapping, if one was allocated.

		2. If the MDL was built by a call to the MmBuildMdlForNonPagedPool routine, MmGetSystemAddressForMdlSafe reuses the existing system-address-space
		mapping instead of creating a new one. In this case, no cleanup is required (that is, unlocking and unmapping are not necessary).

		3. If the MDL was built by a call to the IoBuildPartialMdl routine, the driver must call either the MmPrepareMdlForReuse routine or the IoFreeMdl
		routine to release the system-address-space mapping.

		4. If the MDL was built by a call to the MmAllocatePagesForMdlEx routine, the driver must call the MmUnmapLockedPages routine to release the
		system-address-space mapping. If MmGetSystemAddressForMdlSafe is called more than one time for an MDL, subsequent MmGetSystemAddressForMdlSafe
		calls simply return the mapping that was created by the first call. One call to MmUnmapLockedPages is sufficient to release this mapping.
	*/

	// the returned pointer is the SSDT made writable
	writableSystemServiceDescriptorTable = MmGetSystemAddressForMdlSafe(systemServiceDescriptorTableMdl, HighPagePriority);

	if(!writableSystemServiceDescriptorTable)
	{
		DbgPrint("MmGetSystemAddressForMdlSafe failed\n");

		MmUnlockPages(systemServiceDescriptorTableMdl);

		IoFreeMdl(systemServiceDescriptorTableMdl);

		return FALSE;
	}

	return TRUE;
}

void hookNtFunction(void* zwFunction, void* hookFunction)
{
	if(!writableSystemServiceDescriptorTable && !initializeWritableSystemServiceDescriptorTable())
		return;

	// Write to writableSystemServiceDescriptorTable[X]...
	
	DbgPrint("Hooking... Zw* = 0x%X [index = %d]\n", zwFunction, GET_NT_FUNCTION_SSDT_INDEX(zwFunction));

	void* originalNtFunction = HOOK_NT_FUNCTION(zwFunction, hookFunction, writableSystemServiceDescriptorTable);

	DbgPrint(
				"Hooked.\n"
				"Hook function = 0x%X\n"
				"Original Nt* function = 0x%X\n\n", hookFunction, originalNtFunction);
}

void unhookNtFunction(void* zwFunction)
{
	DbgPrint("Unhooking function whose Zw* = 0x%X and original Nt* = 0x%X\n", zwFunction, GET_NT_FUNCTION_FROM_ZW_FUNCTION(zwFunction));

	void* hookFunction = UNHOOK_NT_FUNCTION(zwFunction, GET_NT_FUNCTION_FROM_ZW_FUNCTION(zwFunction), writableSystemServiceDescriptorTable);

	DbgPrint("Unhooked. The hook function was 0x%X\n\n", hookFunction);
}