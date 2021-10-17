
# nosferatu

Lsass NTLM Authentication Backdoor 

## How it Works

First, the DLL is injected into the `lsass.exe` process, and will begin hooking authentication WinAPI calls. The targeted function is `MsvpPasswordValidate()`, located in `NtlmShared.dll`. In the pursuit of not being detected, the hooked function will call the original function and allow for the normal flow of authentication. Only after seeing that authentication has failed will the hook swap out the actual NTLM hash with the backdoor hash for comparison. 

## Usage

Nosferatu must be compiled as a 64 bit DLL. It must be injected using the a DLL Injector with SeDebugPrivilege.

![injector](photos/injector.png)

You can see it loaded using Procexp:

![loaded](photos/loaded.png)

Login example using Impacket:

![auth](photos/auth.png)

## Limitations

In an Active Directory environment, authentication via RDP, runas, or the lock screen does not work with the `nosferatu` password. Authentication using SMB, WinRM, and WMI is still possible. 

In a non-AD environment, authentication works for all aspects.
