#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <winternl.h>
#include <wintrust.h>
#include <SoftPub.h>
#include <detours.h>
#include <shellapi.h>
#include <fileapi.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")
#define STATUS_ACCESS_DENIED 0xC0000022

typedef NTSTATUS(NTAPI* RealNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* RealNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* RealNtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* RealNtProtectVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef NTSTATUS(NTAPI* RealNtWriteVirtualMemory)(HANDLE, PVOID, LPCVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* RealNtDeleteValueKey)(HANDLE, PUNICODE_STRING);
HANDLE Mutex = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex2 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex3 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex4 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex5 = CreateMutex(NULL, FALSE, NULL);
BOOL XMode = FALSE; //you set the mode you want
BOOL Mini = TRUE; //Mini Mode FALSE/TRUE
HMODULE Module = NULL;

RealNtCreateFile OriginalNtCreateFile = nullptr;
RealNtResumeThread OriginalNtResumeThread = nullptr;
RealNtSetValueKey OriginalNtSetValueKey = nullptr;
RealNtProtectVirtualMemory OriginalNtProtectVirtualMemory = nullptr;
RealNtWriteVirtualMemory OriginalNtWriteVirtualMemory = nullptr;
RealNtDeleteValueKey OriginalNtDeleteValueKey = nullptr;

BOOL IsSigned(HANDLE hProcess)
{
    bool isSigned = false;
    TCHAR szFileName[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, szFileName, MAX_PATH) > 0)
    {
        WINTRUST_FILE_INFO FileData = { 0 };
        WINTRUST_DATA TrustData = { 0 };
        FileData.cbStruct = sizeof(FileData);
        FileData.pcwszFilePath = szFileName;
        FileData.hFile = NULL;
        FileData.pgKnownSubject = NULL;
        TrustData.cbStruct = sizeof(TrustData);
        TrustData.dwUIChoice = WTD_UI_NONE;
        TrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        TrustData.dwUnionChoice = WTD_CHOICE_FILE;
        TrustData.pFile = &FileData;
        TrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        TrustData.hWVTStateData = NULL;
        TrustData.pwszURLReference = NULL;
        TrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        GUID Guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG IsSigned = WinVerifyTrust(NULL, &Guid, &TrustData);
        if (IsSigned == ERROR_SUCCESS)
        {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL IsRunningAsService()
{
    BOOL IsService = FALSE;
    TCHAR ModuleName[MAX_PATH];
    DWORD Size = sizeof(ModuleName);
    if (GetModuleFileName(NULL, ModuleName, Size) == 0) {
        return FALSE;
    }
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) {
        return FALSE;
    }
    SC_HANDLE hService = OpenService(hSCM, ModuleName, SERVICE_QUERY_CONFIG);
    if (hService != NULL)
    {
        DWORD bytesNeeded;
        LPQUERY_SERVICE_CONFIG ServiceConf = NULL;
        if (QueryServiceConfig(hService, ServiceConf, 0, &bytesNeeded) || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            ServiceConf = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, bytesNeeded);
            if (ServiceConf != NULL) {
                if (QueryServiceConfig(hService, ServiceConf, bytesNeeded, &bytesNeeded))
                {
                    IsService = (ServiceConf->dwServiceType == SERVICE_WIN32_OWN_PROCESS);
                }
                LocalFree(ServiceConf);
            }
        }
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCM);
    return IsService;
}

bool hasEnding(std::string const& fullString, std::string const& ending)
{
    if (fullString.length() >= ending.length())
    {
        return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
    }
    return false;
}

bool IsBrowser(char* FileName)
{
    BOOL Signed = IsSigned(GetCurrentProcess());
    if (hasEnding(FileName, "msedge.exe") && Signed)
    {
        return true;
    }

    if (hasEnding(FileName, "firefox.exe") && Signed)
    {
        return true;
    }
    if (hasEnding(FileName, "vivaldi.exe") && Signed)
    {
        return true;
    }
    if (hasEnding(FileName, "chrome.exe") && Signed)
    {
        return true;
    }

    if (hasEnding(FileName, "brave.exe") && Signed)
    {
        return true;
    }

    if (hasEnding(FileName, "browser.exe") && Signed)
    {
        return true;
    }

    if (hasEnding(FileName, "opera.exe") && Signed)
    {
        return true;
    }

    if (hasEnding(FileName, "waterfox.exe") && Signed)
    {
        return true;
    }

    return false;
}

BOOL IsBlacklistedApp(char* FileName, BOOL Signed)
{
    if (hasEnding(FileName, "javaw.exe") && Signed || hasEnding(FileName, "py.exe") && Signed || hasEnding(FileName, "python.exe") && Signed || hasEnding(FileName, "pythonw.exe") && Signed || hasEnding(FileName, "explorer.exe") && Signed || std::string(FileName).find("C:\\Windows\\Microsoft.NET\\Framework") == 0)
        return true;
    return false;
}

BOOL IsProcessAllowed()
{
    char FileName[MAX_PATH + 1];
    GetModuleFileNameExA(GetCurrentProcess(), NULL, FileName, MAX_PATH);
    BOOL Signed = IsSigned(GetCurrentProcess());
    if (XMode)
    {
        if (IsBrowser(FileName))
            return true;
    }
    else
    {
        if (IsBlacklistedApp(FileName, Signed))
            return false;
    }
    if (XMode)
        return false;
    return true;
}

BOOL IsNoMoreCookiesInstaller()
{
    unsigned int Sum = 0;
    char Buffer[1024];
    DWORD BytesRead;
    WCHAR FileName[MAX_PATH + 1];
    if (!K32GetModuleFileNameExW(GetCurrentProcess(), NULL, FileName, MAX_PATH))
        return false;
    HANDLE hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        while (ReadFile(hFile, Buffer, sizeof(Buffer), &BytesRead, NULL) && BytesRead > 0)
        {
            for (DWORD i = 0; i < BytesRead; i++)
            {
                Sum += Buffer[i];
            }
        }
        WCHAR CheckSum[9];
        swprintf_s(CheckSum, 9, L"%08X", Sum);
        if (wcscmp(CheckSum, L"000C66AD") == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL IsSandboxedProcess()
{
    HANDLE hToken = NULL;
    DWORD dwLengthNeeded = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return TRUE;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        CloseHandle(hToken);
        return TRUE;
    }
    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
    if (!pTIL)
    {
        CloseHandle(hToken);
        return TRUE;
    }
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
    {
        DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID || dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
        {
            return TRUE;
        }
    }
    LocalFree(pTIL);
    CloseHandle(hToken);
    return FALSE;
}

DWORD WINAPI ShowNotification(std::wstring Text)
{
    NOTIFYICONDATAW nid = { sizeof(nid) };
    nid.uFlags = NIF_INFO;
    nid.hWnd = NULL;
    nid.dwInfoFlags = NIIF_ERROR;
    nid.hIcon = LoadIcon(NULL, IDI_ERROR);
    nid.uTimeout = 7000;
    nid.cbSize = sizeof(nid);
    wcsncpy_s(nid.szInfoTitle, L"Unauthorized Action", _TRUNCATE);
    wcsncpy_s(nid.szInfo, Text.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_ADD, &nid);
    return 0;
}

std::wstring UserPath(L"C:\\Users\\");
std::wstring EdgePath;
std::wstring BravePath;
std::wstring ChromePath;
std::wstring FirefoxPath;
std::wstring YandexPath;
std::wstring OperaPath;
std::wstring WaterfoxPath;
std::wstring VivaldiPath;
BOOL Startup()
{
    wchar_t Username[50];
    DWORD UsernameLen = 50 - 1;
    if (GetUserNameW(Username, &UsernameLen))
    {
        UserPath = L"\\??\\C:\\Users\\";
        UserPath.append(Username);
        UserPath.append(L"\\");
        EdgePath = UserPath.c_str();
        EdgePath.append(L"AppData\\Local\\Microsoft\\Edge\\User Data");
        BravePath = UserPath.c_str();
        BravePath.append(L"AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data");
        ChromePath = UserPath.c_str();
        ChromePath.append(L"AppData\\Local\\Google\\Chrome\\User Data");
        FirefoxPath = UserPath.c_str();
        FirefoxPath.append(L"AppData\\Roaming\\Mozilla\\Firefox\\Profiles");
        YandexPath = UserPath.c_str();
        YandexPath.append(L"AppData\\Local\\Yandex\\YandexBrowser\\User Data");
        OperaPath = UserPath.c_str();
        OperaPath.append(L"AppData\\Roaming\\Opera Software\\Opera Stable");
        WaterfoxPath = UserPath.c_str();
        WaterfoxPath.append(L"AppData\\Roaming\\Waterfox\\Profiles");
        VivaldiPath = UserPath.c_str();
        VivaldiPath.append(L"AppData\\Local\\Vivaldi\\User Data");
        return true;
    }
    else
    {
        return false;
    }
}

BOOL IsBlacklistedPath(LPCWSTR FilePath)
{
    std::wstring WFilePath(FilePath);
    if (WFilePath.rfind(EdgePath.c_str(), 0) == 0 ||
        WFilePath.rfind(BravePath.c_str(), 0) == 0 ||
        WFilePath.rfind(ChromePath.c_str(), 0) == 0 ||
        WFilePath.rfind(FirefoxPath.c_str(), 0) == 0 ||
        WFilePath.rfind(YandexPath.c_str(), 0) == 0 ||
        WFilePath.rfind(OperaPath.c_str(), 0) == 0 ||
        WFilePath.rfind(WaterfoxPath.c_str(), 0) == 0 ||
        WFilePath.rfind(VivaldiPath.c_str(), 0) == 0)
    {
        return true;
    }
    return false;
}

BOOL AlreadyShown = FALSE;
NTSTATUS NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    WaitForSingleObject(Mutex, INFINITE);
    if (ObjectAttributes != nullptr && ObjectAttributes->ObjectName != nullptr)
    {
        std::wstring fileName(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
        if (IsBlacklistedPath(fileName.c_str()))
        {
            if (!AlreadyShown)
            {
                std::wstring NotificationString(L"NoMoreCookies: A process tried to access a restricted browser path, which was denied successfully.");
                ShowNotification(NotificationString);
                AlreadyShown = TRUE;
            }
            ReleaseMutex(Mutex);
            return STATUS_ACCESS_DENIED;
        }
    }
    ReleaseMutex(Mutex);
    return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI HookedNtResumeThread(HANDLE Thread, PULONG SuspendCount)
{
    WaitForSingleObject(Mutex2, INFINITE);
    DWORD PID = GetProcessIdOfThread(Thread);
    if (PID != GetCurrentProcessId())
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
        char DllPath[MAX_PATH];
        GetModuleFileNameA(Module, DllPath, MAX_PATH);
        LPVOID LoadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        LPVOID Allocation = VirtualAllocEx(hProcess, NULL, strlen(DllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(hProcess, Allocation, DllPath, strlen(DllPath), NULL);
        HANDLE InjectionThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, Allocation, 0, NULL);
        WaitForSingleObject(InjectionThread, INFINITE);
        VirtualFreeEx(hProcess, Allocation, strlen(DllPath), MEM_RELEASE);
        CloseHandle(InjectionThread);
        CloseHandle(hProcess);
    }
    ReleaseMutex(Mutex2);
    return OriginalNtResumeThread(Thread, SuspendCount);
}

NTSTATUS NTAPI HookedNtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
{
    WaitForSingleObject(Mutex3, INFINITE);
    if (ValueName != NULL && ValueName->Buffer != NULL && Type == REG_SZ && wcsstr(ValueName->Buffer, L"AppInit_DLLs") || ValueName != NULL && ValueName->Buffer != NULL && Type == REG_DWORD && wcsstr(ValueName->Buffer, L"LoadAppInit_DLLs"))
    {
        ReleaseMutex(Mutex3);
        return STATUS_ACCESS_DENIED;
    }
    ReleaseMutex(Mutex3);
    return OriginalNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

FARPROC NtCreateFileAddress = NULL;
FARPROC NtResumeThreadAddress = NULL;
FARPROC NtSetValueKeyAddress = NULL;
FARPROC NtWriteVirtualMemory = NULL;
FARPROC NtProtectVirtualMemory = NULL;

NTSTATUS NTAPI HookedNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
    WaitForSingleObject(Mutex4, INFINITE);
    if (GetProcessId(ProcessHandle) == GetCurrentProcessId())
    {
        if ((int)(*BaseAddress) == (int)(NtCreateFileAddress) || (int)(*BaseAddress) == (int)(NtResumeThreadAddress) || (int)(*BaseAddress) == (int)(NtSetValueKeyAddress) || (int)(*BaseAddress) == (int)(NtWriteVirtualMemory) || (int)(*BaseAddress) == (int)(NtProtectVirtualMemory))
        {
            ReleaseMutex(Mutex4);
            return STATUS_ACCESS_DENIED;
        }
    }
    ReleaseMutex(Mutex4);
    return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
{
    WaitForSingleObject(Mutex5, INFINITE);
    if (GetProcessId(ProcessHandle) == GetCurrentProcessId())
    {
        if ((int)(BaseAddress) == (int)(NtCreateFileAddress) || (int)(BaseAddress) == (int)(NtResumeThreadAddress) || (int)(BaseAddress) == (int)(NtSetValueKeyAddress) || (int)(BaseAddress) == (int)(NtWriteVirtualMemory) || (int)(BaseAddress) == (int)(NtProtectVirtualMemory))
        {
            ReleaseMutex(Mutex5);
            return STATUS_ACCESS_DENIED;
        }
    }
    ReleaseMutex(Mutex5);
    return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

void CheckHook()
{
    NtCreateFileAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
    NtResumeThreadAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeThread");
    NtSetValueKeyAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetValueKey");
    NtWriteVirtualMemory = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
    NtProtectVirtualMemory = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");
    const char* Functions[] = { "NtCreateFile", "NtResumeThread", "NtSetValueKey", "NtProtectVirtualMemory", "NtWriteVirtualMemory" };
    const int Size = sizeof(Functions) / sizeof(Functions[0]);
    while (true)
    {
        Sleep(2000);
        for (int i = 0; i < Size; i++)
        {
            FARPROC FunctionAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), Functions[i]);
            BYTE* StartAddressBytes = (BYTE*)FunctionAddress;
            if (StartAddressBytes[0] != 0xE9 || StartAddressBytes[0] == 0xCC)
            {
                ExitProcess(0);
            }
        }
    }
}

void HookingThread()
{
    if (Startup())
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        OriginalNtCreateFile = reinterpret_cast<RealNtCreateFile>(DetourFindFunction("ntdll.dll", "NtCreateFile"));
        DetourAttach(&(LPVOID&)OriginalNtCreateFile, HookedNtCreateFile);
        if (!Mini)
        {
            OriginalNtResumeThread = reinterpret_cast<RealNtResumeThread>(DetourFindFunction("ntdll.dll", "NtResumeThread"));
            DetourAttach(&(LPVOID&)OriginalNtResumeThread, HookedNtResumeThread);
            OriginalNtSetValueKey = reinterpret_cast<RealNtSetValueKey>(DetourFindFunction("ntdll.dll", "NtSetValueKey"));
            DetourAttach(&(LPVOID&)OriginalNtSetValueKey, HookedNtSetValueKey);
            OriginalNtProtectVirtualMemory = reinterpret_cast<RealNtProtectVirtualMemory>(DetourFindFunction("ntdll.dll", "NtProtectVirtualMemory"));
            DetourAttach(&(LPVOID&)OriginalNtProtectVirtualMemory, HookedNtProtectVirtualMemory);
            OriginalNtWriteVirtualMemory = reinterpret_cast<RealNtWriteVirtualMemory>(DetourFindFunction("ntdll.dll", "NtWriteVirtualMemory"));
            DetourAttach(&(LPVOID&)OriginalNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
        }
        DetourTransactionCommit();
        if (!Mini)
        {
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CheckHook, NULL, 0, NULL);
        }
    }
    else
    {
        std::wstring ErrorMessage(L"NoMoreCookies: Couldn't Initiate Startup Code.");
        ShowNotification(ErrorMessage);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        if (!IsSandboxedProcess())
        {
            if (!IsNoMoreCookiesInstaller())
            {
                Module = hModule;
                if (!XMode)
                {
                    if ((!IsProcessAllowed() || !IsSigned(GetCurrentProcess())) && !IsRunningAsService())
                    {
                        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HookingThread, NULL, NULL, NULL);
                    }
                }
                else
                {
                    if (!IsProcessAllowed() && !IsRunningAsService())
                    {
                        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HookingThread, NULL, NULL, NULL);
                    }
                }
            }
        }
    }
    return TRUE;
}