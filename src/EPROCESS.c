#include "EPROCESS.h"

void getProcessImageFileName(EPROCESS* process, UNICODE_STRING* imageFileName)
{
	if(!process->SeAuditProcessCreationInfo.ImageFileName ||
		!process->SeAuditProcessCreationInfo.ImageFileName->Name.Buffer)
	{
		// could also do: imageFileName = EPROCESS->ImageFileName (kd> dt nt!_eprocess: 0x16c ImageFileName : [15] UChar)
		// but the ImageFileName not only might not be null terminated but it's also a UChar (not WCHAR) array,
		// and initializing a UNICODE_STRING with it would be a pain
		RtlZeroMemory(imageFileName, sizeof(*imageFileName));

		DbgPrint("process->SeAuditProcessCreationInfo.ImageFileName or .ImageFileName->Name.Buffer is NULL in process %X\n", process);
		
		return;
	}
	
	UNICODE_STRING* imageFileNamePath = &process->SeAuditProcessCreationInfo.ImageFileName->Name;

	WCHAR* temporaryImageFileName = (BYTE*)imageFileNamePath->Buffer + imageFileNamePath->Length - 2;
	
	// -1 because without it there will be: `processName = \<name>`, not: `processName = <name>`
	//
	// temporaryImageFileName > (BYTE*)imageFileNamePath->Buffer because it could be the same name, with no '\\'
	// and then we'd go behind the string
	while(temporaryImageFileName > (BYTE*)imageFileNamePath->Buffer && *(temporaryImageFileName - 1) != '\\')
		temporaryImageFileName--;

	imageFileName->Buffer = temporaryImageFileName;
	imageFileName->Length = wcslen(temporaryImageFileName) * sizeof(WCHAR);
	imageFileName->MaximumLength = imageFileName->Length + sizeof(WCHAR);
}