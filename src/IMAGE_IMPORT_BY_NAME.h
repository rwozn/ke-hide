#pragma once

typedef char CHAR;
typedef unsigned short WORD;

//
// Import Format
//
typedef struct _IMAGE_IMPORT_BY_NAME
{
	WORD    Hint;
	CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
