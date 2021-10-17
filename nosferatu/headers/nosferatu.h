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


typedef BOOLEAN(WINAPI* pMsvpPasswordValidate)(BOOLEAN, NETLOGON_LOGON_INFO_CLASS, PVOID, void*, PULONG, PUSER_SESSION_KEY, PVOID);
extern pMsvpPasswordValidate MsvpPasswordValidate;


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