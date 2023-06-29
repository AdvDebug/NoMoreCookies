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
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#define STATUS_ACCESS_DENIED 0xC0000022

typedef NTSTATUS(NTAPI* RealNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
HANDLE Mutex = CreateMutex(NULL, FALSE, NULL);

RealNtCreateFile OriginalNtCreateFile = nullptr;

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

bool hasEnding(std::string const& fullString, std::string const& ending) {
    if (fullString.length() >= ending.length())
    {
        return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
    }
    return false;
}

BOOL IsProcessAllowed()
{
    char FileName[MAX_PATH + 1];
    GetModuleFileNameExA(GetCurrentProcess(), NULL, FileName, MAX_PATH);
    if (hasEnding(FileName, "javaw.exe") || hasEnding(FileName, "py.exe") || hasEnding(FileName, "python.exe") || hasEnding(FileName, "pythonw.exe"))
        return false;
    return true;
}

DWORD WINAPI ShowNotification(std::wstring Text)
{
    NOTIFYICONDATAW nid = { sizeof(nid) };
    nid.uFlags = NIF_INFO;
    nid.hWnd = NULL;
    nid.uID = 1;
    nid.dwInfoFlags = NIIF_ERROR;
    nid.hIcon = LoadIcon(NULL, IDI_ERROR);
    nid.uTimeout = 7000;
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
    if (WFilePath.rfind(EdgePath.c_str(), 0) == 0 || WFilePath.rfind(BravePath.c_str(), 0) == 0 || WFilePath.rfind(ChromePath.c_str(), 0) == 0 || WFilePath.rfind(FirefoxPath.c_str(), 0) == 0)
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
                std::wstring NotificationString(L"NoMoreCookies: The Process tried to Access a Restriced Browser Path, which was denied successfully.");
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

void CheckHook()
{
    while (true)
    {
        Sleep(2000);
        FARPROC NtCreateFileAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
        LPVOID NtCreateFileStartAddress = (LPVOID)NtCreateFileAddress;
        BYTE* StartAddressBytes = (BYTE*)NtCreateFileStartAddress;
        if (StartAddressBytes[0] != 0xE9 || StartAddressBytes[0] == 0xCC)
        {
            ExitProcess(0);
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
        DetourTransactionCommit();
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CheckHook, NULL, 0, NULL);
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
        if ((!IsProcessAllowed() || !IsSigned(GetCurrentProcess())) && !IsRunningAsService())
        {
            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HookingThread, NULL, NULL, NULL);
        }
    }
    return TRUE;
}