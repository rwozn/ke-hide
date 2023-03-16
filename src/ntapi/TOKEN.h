#pragma once

#include <ntifs.h>

typedef struct
{
	UCHAR PerUserPolicy[27];
} TOKEN_AUDIT_POLICY_;

typedef struct
{
	// TOKEN_AUDIT_POLICY is already defined and contains 29 elements instead of 27
	TOKEN_AUDIT_POLICY_ AdtTokenPolicy;

	UCHAR PolicySetStatus;
} SEP_AUDIT_POLICY;

typedef struct
{
	DWORD64 Present;
	DWORD64 Enabled;
	DWORD64 EnabledByDefault;
} SEP_TOKEN_PRIVILEGES;

typedef struct
{
	ULONG SecurityAttributeCount;
	LIST_ENTRY SecurityAttributesList;

	ULONG WorkingSecurityAttributeCount;
	LIST_ENTRY WorkingSecurityAttributesList;
} AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct
{
	PVOID /*PSEP_LOGON_SESSION_REFERENCES*/ Next;
	LUID LogonId;
	LUID BuddyLogonId;
	ULONG ReferenceCount;
	ULONG Flags;
	PVOID /*PDEVICE_MAP*/ pDeviceMap;
	PVOID Token;
	UNICODE_STRING AccountName;
	UNICODE_STRING AuthorityName;
} SEP_LOGON_SESSION_REFERENCES;

typedef struct
{
	TOKEN_SOURCE TokenSource;
	LUID TokenId;
	LUID AuthenticationId;
	LUID ParentTokenId;
	LARGE_INTEGER ExpirationTime;
	PERESOURCE TokenLock;
	LUID ModifiedId;
	SEP_TOKEN_PRIVILEGES Privileges;
	SEP_AUDIT_POLICY AuditPolicy;
	ULONG SessionId;
	ULONG UserAndGroupCount;
	ULONG RestrictedSidCount;
	ULONG VariableLength;
	ULONG DynamicCharged;
	ULONG DynamicAvailable;
	ULONG DefaultOwnerIndex;
	PSID_AND_ATTRIBUTES UserAndGroups;
	PSID_AND_ATTRIBUTES RestrictedSids;
	PVOID PrimaryGroup;
	ULONG* DynamicPart;
	PACL DefaultDacl;
	TOKEN_TYPE TokenType;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	ULONG TokenFlags;
	UCHAR TokenInUse;
	ULONG IntegrityLevelIndex;
	ULONG MandatoryPolicy;
	SEP_LOGON_SESSION_REFERENCES* LogonSession;
	LUID OriginatingLogonSession;
	SID_AND_ATTRIBUTES_HASH SidHash;
	SID_AND_ATTRIBUTES_HASH RestrictedSidHash;
	AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes;
	PVOID SessionObject;
	ULONG VariablePart;
} TOKEN;