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
#include <filesystem>
#include <unordered_map>
#include <tchar.h>
#include <algorithm>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "amsi.lib")
#pragma comment(lib, "crypt32.lib")
#define STATUS_ACCESS_DENIED 0xC0000022
typedef NTSTATUS(NTAPI* RealNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* RealNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* RealNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* RealNtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* RealNtProtectVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef NTSTATUS(NTAPI* RealNtWriteVirtualMemory)(HANDLE, PVOID, LPCVOID, SIZE_T, PSIZE_T);
typedef DWORD(WINAPI* RealCreateProcessInternalW)(DWORD, LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION, DWORD);
typedef NTSTATUS(WINAPI* RealNtDeleteValueKey)(HANDLE, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* RealNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
HANDLE Mutex = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex2 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex3 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex4 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex5 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex6 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex7 = CreateMutex(NULL, FALSE, NULL);
HANDLE Mutex8 = CreateMutex(NULL, FALSE, NULL);
BOOL XMode = FALSE; //you set the mode you want
BOOL Mini = TRUE; //Mini Mode FALSE/TRUE
HMODULE Module = NULL;
HANDLE ProtectionThread = NULL;
HANDLE WatchingThread = NULL;
BOOL WatchThread = FALSE;
BOOL Signed = FALSE;
BOOL Signed2 = FALSE;
BOOL Signed3 = FALSE;

RealNtCreateFile OriginalNtCreateFile = nullptr;
RealNtOpenFile OriginalNtOpenFile = nullptr;
RealNtResumeThread OriginalNtResumeThread = nullptr;
RealNtSetValueKey OriginalNtSetValueKey = nullptr;
RealCreateProcessInternalW OriginalCreateProcessInternalW = nullptr;
RealNtDeleteValueKey OriginalNtDeleteValueKey = nullptr;
RealNtProtectVirtualMemory OriginalNtProtectVirtualMemory = nullptr;
RealNtWriteVirtualMemory OriginalNtWriteVirtualMemory = nullptr;
RealNtReadVirtualMemory OriginalNtReadVirtualMemory = nullptr;

LPWSTR GetPublisherName(const wchar_t* FilePath)
{
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    DWORD dwEncoding = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    DWORD dwCertNameSize = 0;
    LPWSTR szCertName = NULL;
    HCRYPTMSG Msg = { 0 };
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    CERT_INFO CertInfo;
    DWORD dwSignerInfo = 0;
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, FilePath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType, &hCertStore, &Msg, NULL))
    {
        if (CryptMsgGetParam(Msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo))
        {
            pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
            if (CryptMsgGetParam(Msg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo))
            {
                CertInfo.Issuer = pSignerInfo->Issuer;
                CertInfo.SerialNumber = pSignerInfo->SerialNumber;
                pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);
                dwCertNameSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
                szCertName = (LPWSTR)malloc((dwCertNameSize + 1) * sizeof(WCHAR));
                CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szCertName, dwCertNameSize);
                CertFreeCertificateContext(pCertContext);
                CertCloseStore(hCertStore, 0);
                LocalFree(pSignerInfo);
                return szCertName;
            }
        }
    }
}

bool hasEnding(std::string const& fullString, std::string const& ending)
{
    if (fullString.length() >= ending.length())
    {
        return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
    }
    return false;
}

bool IsBrowser(char* FileName, BOOL FirstTime)
{
    const char* Browsers[] = { "msedge.exe", "firefox.exe", "vivaldi.exe", "chrome.exe", "brave.exe", "browser.exe", "opera.exe", "waterfox.exe" };
    const int Size = sizeof(Browsers) / sizeof(Browsers[0]);
    if (FirstTime)
    {
        for (int i = 0; i < Size; i++)
        {
            if (hasEnding(FileName, Browsers[i]))
                return true;
        }
    }
    else
    {
        for (int i = 0; i < Size; i++)
        {
            if (hasEnding(FileName, Browsers[i]) && Signed)
                return true;
        }
    }
    return false;
}

BOOL IsSigned(HANDLE hProcess, BOOL OnlyBrowsers)
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
            if (OnlyBrowsers)
            {
                std::wstring Publisher(GetPublisherName(szFileName));
                if (Publisher.c_str() != NULL)
                {
                    BOOL Isbrowser = FALSE;
                    BOOL IsTrustedPublisher = FALSE;
                    size_t Size = 0;
                    wcstombs_s(&Size, NULL, 0, szFileName, wcslen(szFileName));
                    char* FileName = (char*)malloc(Size + 1);
                    wcstombs_s(NULL, FileName, Size + 1, szFileName, wcslen(szFileName));
                    if (FileName != NULL)
                    {
                        if (IsBrowser(FileName, TRUE))
                            Isbrowser = TRUE;
                        const wchar_t* PublisherName = Publisher.c_str();
                        const wchar_t* Publishers[] = { L"mozilla", L"microsoft", L"brave", L"waterfox", L"yandex", L"opera", L"vivaldi" };
                        int Size2 = sizeof(Publishers) / sizeof(Publishers[0]);
                        wchar_t LowercasePublisher[100];
                        wcscpy_s(LowercasePublisher, 256, PublisherName);
                        for (int i = 0; LowercasePublisher[i] != L'\0'; i++)
                            LowercasePublisher[i] = towlower(LowercasePublisher[i]);
                        for (int i = 0; i < Size2; i++)
                        {
                            if (wcsstr(LowercasePublisher, Publishers[i]) != NULL)
                            {
                                IsTrustedPublisher = TRUE;
                                break;
                            }
                        }
                        free(FileName);
                    }
                    if (Isbrowser && IsTrustedPublisher)
                        return TRUE;
                }
                return FALSE;
            }
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

BOOL IsBlacklistedApp(wchar_t* FileNamez)
{
    if (Signed2)
    {
        BOOL IsBlacklistedPublisher = FALSE;
        std::wstring Publisher(GetPublisherName(FileNamez));
        if (Publisher.c_str() != NULL)
        {
            const wchar_t* PublisherName = Publisher.c_str();
            const wchar_t* Publishers[] = { L"python", L"oracle" };
            int Size3 = sizeof(Publishers) / sizeof(Publishers[0]);
            wchar_t LowercasePublisher[100];
            wcscpy_s(LowercasePublisher, 256, PublisherName);
            for (int i = 0; LowercasePublisher[i] != L'\0'; i++)
                LowercasePublisher[i] = towlower(LowercasePublisher[i]);
            for (int i = 0; i < Size3; i++)
            {
                if (wcsstr(LowercasePublisher, Publishers[i]) != NULL)
                {
                    IsBlacklistedPublisher = TRUE;
                    break;
                }
            }
        }
        return IsBlacklistedPublisher && Signed2;
    }
    return false;
}

BOOL IsExplorer()
{
    char FileName[MAX_PATH + 1];
    GetModuleFileNameExA(GetCurrentProcess(), NULL, FileName, MAX_PATH);
    if (hasEnding(FileName, "explorer.exe"))
        return true;
    return false;
}

BOOL IsProcessAllowed()
{
    wchar_t FileName[MAX_PATH + 1];
    GetModuleFileNameEx(GetCurrentProcess(), NULL, FileName, MAX_PATH);
    if (IsBlacklistedApp(FileName) || IsExplorer())
        return false;
    return true;
}

std::unordered_map<HANDLE, bool> Cache;

bool IsProcessSigned(HANDLE hProcess, BOOL OnlyBrowsers)
{
    auto it = Cache.find(hProcess);
    if (it != Cache.end())
    {
        return it->second;
    }
    bool IsSignedProcess = IsSigned(hProcess, OnlyBrowsers);
    Cache[hProcess] = IsSignedProcess;
    return IsSignedProcess;
}

BOOL IsNoMoreCookiesInstaller(HANDLE hProcess)
{
    unsigned int Sum = 0;
    char Buffer[1024];
    DWORD BytesRead;
    WCHAR FileName[MAX_PATH + 1];
    if (!K32GetModuleFileNameExW(hProcess, NULL, FileName, MAX_PATH))
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
        CloseHandle(hFile);
        WCHAR CheckSum[9];
        swprintf_s(CheckSum, 9, L"%08X", Sum);
        if (wcscmp(CheckSum, L"0010494B") == 0)
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
    Shell_NotifyIconW(NIM_DELETE, &nid);
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


BOOL Isx64Process(HANDLE hProcess)
{
    BOOL is64BitProcess = FALSE;
    IsWow64Process(hProcess, &is64BitProcess);
    return !is64BitProcess;
}

BOOL IsSameArch(HANDLE hProcess)
{
    if (Isx64Process(GetCurrentProcess()) == Isx64Process(hProcess))
        return true;
    return false;
}

std::wstring ProgramName[256];

BOOL AlreadyShown = FALSE;
NTSTATUS NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    WaitForSingleObject(Mutex, INFINITE);
    if (ObjectAttributes != nullptr && ObjectAttributes->ObjectName != nullptr)
    {
        std::wstring FileName(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
        if (IsBlacklistedPath(FileName.c_str()))
        {
            if (!AlreadyShown)
            {
                if (ProgramName->c_str() != NULL)
                {
                    std::wstring NotificationString(L"NoMoreCookies: The process ");
                    NotificationString.append(L"\"");
                    NotificationString.append(ProgramName->c_str());
                    NotificationString.append(L"\"");
                    NotificationString.append(L" tried to access a restricted browser path, which was denied successfully.");
                    ShowNotification(NotificationString);
                }
                else
                {
                    std::wstring NotificationString(L"NoMoreCookies: A Process tried to access a restricted browser path, which was denied successfully.");
                    ShowNotification(NotificationString);
                }
                AlreadyShown = TRUE;
            }
            ReleaseMutex(Mutex);
            return STATUS_ACCESS_DENIED;
        }
    }
    ReleaseMutex(Mutex);
    return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI HookedNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
    WaitForSingleObject(Mutex2, INFINITE);
    if (ObjectAttributes != nullptr && ObjectAttributes->ObjectName != nullptr)
    {
        std::wstring FileName(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
        if (IsBlacklistedPath(FileName.c_str()))
        {
            if (!AlreadyShown)
            {
                if (ProgramName->c_str() != NULL)
                {
                    std::wstring NotificationString(L"NoMoreCookies: The process ");
                    NotificationString.append(L"\"");
                    NotificationString.append(ProgramName->c_str());
                    NotificationString.append(L"\"");
                    NotificationString.append(L" tried to access a restricted browser path, which was denied successfully.");
                    ShowNotification(NotificationString);
                }
                else
                {
                    std::wstring NotificationString(L"NoMoreCookies: A Process tried to access a restricted browser path, which was denied successfully.");
                    ShowNotification(NotificationString);
                }
                AlreadyShown = TRUE;
            }
            ReleaseMutex(Mutex2);
            return STATUS_ACCESS_DENIED;
        }
    }
    ReleaseMutex(Mutex2);
    return OriginalNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

BOOL Inject(int PID)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (IsSameArch(hProcess))
    {
        char DllPath[MAX_PATH];
        GetModuleFileNameA(Module, DllPath, MAX_PATH);
        LPVOID LoadLibraryAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
        if (LoadLibraryAddress != NULL)
        {
            LPVOID Allocation = VirtualAllocEx(hProcess, NULL, strlen(DllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            WriteProcessMemory(hProcess, Allocation, DllPath, strlen(DllPath), NULL);
            HANDLE InjectionThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, Allocation, 0, NULL);
            WaitForSingleObject(InjectionThread, INFINITE);
            VirtualFreeEx(hProcess, Allocation, strlen(DllPath), MEM_RELEASE);
            CloseHandle(InjectionThread);
            CloseHandle(hProcess);
            return true;
        }
    }
    return false;
}

NTSTATUS NTAPI HookedNtResumeThread(HANDLE Thread, PULONG SuspendCount)
{
    WaitForSingleObject(Mutex3, INFINITE);
    DWORD PID = GetProcessIdOfThread(Thread);
    if (PID != GetCurrentProcessId())
    {
        Inject(PID);
    }
    ReleaseMutex(Mutex3);
    return OriginalNtResumeThread(Thread, SuspendCount);
}

NTSTATUS NTAPI HookedNtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
{
    WaitForSingleObject(Mutex4, INFINITE);
    if (ValueName != NULL && ValueName->Buffer != NULL && Type == REG_SZ && wcsstr(ValueName->Buffer, L"AppInit_DLLs") || ValueName != NULL && ValueName->Buffer != NULL && Type == REG_DWORD && wcsstr(ValueName->Buffer, L"LoadAppInit_DLLs"))
    {
        ReleaseMutex(Mutex4);
        return STATUS_ACCESS_DENIED;
    }
    ReleaseMutex(Mutex4);
    return OriginalNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

NTSTATUS NTAPI HookedNtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName)
{
    WaitForSingleObject(Mutex7, INFINITE);
    if (wcsstr(ValueName->Buffer, L"AppInit_DLLs") || wcsstr(ValueName->Buffer, L"LoadAppInit_DLLs"))
    {
        ReleaseMutex(Mutex7);
        return STATUS_ACCESS_DENIED;
    }
    ReleaseMutex(Mutex7);
    return OriginalNtDeleteValueKey(KeyHandle, ValueName);
}

FARPROC NtCreateFileAddress = NULL;
FARPROC NtOpenFileAddress = NULL;
FARPROC NtResumeThreadAddress = NULL;
FARPROC NtSetValueKeyAddress = NULL;
FARPROC NtDeleteValueKeyAddress = NULL;
FARPROC NtWriteVirtualMemoryAddress = NULL;
FARPROC NtProtectVirtualMemoryAddress = NULL;
FARPROC NtReadVirtualMemoryAddress = NULL;
LPVOID NtdllBaseAddress = NULL;

NTSTATUS NTAPI HookedNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
    WaitForSingleObject(Mutex5, INFINITE);
    if (GetProcessId(ProcessHandle) == GetCurrentProcessId())
    {
        if ((int)(*BaseAddress) == (int)(NtCreateFileAddress) || (int)(*BaseAddress) == (int)(NtOpenFileAddress) || (int)(*BaseAddress) == (int)(NtResumeThreadAddress) || (int)(*BaseAddress) == (int)(NtSetValueKeyAddress) || (int)(*BaseAddress) == (int)(NtDeleteValueKeyAddress) || (int)(*BaseAddress) == (int)(NtdllBaseAddress) || (int)(*BaseAddress) == (int)(NtWriteVirtualMemoryAddress) || (int)(*BaseAddress) == (int)(NtProtectVirtualMemoryAddress) || (int)(*BaseAddress) == (int)(NtReadVirtualMemoryAddress))
        {
            ReleaseMutex(Mutex5);
            return STATUS_ACCESS_DENIED;
        }
    }
    ReleaseMutex(Mutex5);
    return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

BOOL AlreadyShown2 = FALSE;

NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
{
    WaitForSingleObject(Mutex6, INFINITE);
    if (GetProcessId(ProcessHandle) == GetCurrentProcessId())
    {
        if ((int)(BaseAddress) == (int)(NtCreateFileAddress) || (int)(BaseAddress) == (int)(NtResumeThreadAddress) || (int)(BaseAddress) == (int)(NtSetValueKeyAddress) || (int)(BaseAddress) == (int)(NtDeleteValueKeyAddress) || (int)(BaseAddress) == (int)(NtWriteVirtualMemoryAddress) || (int)(BaseAddress) == (int)(NtProtectVirtualMemoryAddress) || (int)(BaseAddress) == (int)(NtReadVirtualMemoryAddress))
        {
            ReleaseMutex(Mutex6);
            return STATUS_ACCESS_DENIED;
        }
    }
    else if (XMode && !Signed2)
    {
        if (IsProcessSigned(ProcessHandle, XMode))
        {
            wchar_t ImageFileName[MAX_PATH + 1];
            if (GetProcessImageFileName(ProcessHandle, ImageFileName, MAX_PATH))
            {
                std::wstring ProcessName(ImageFileName);
                size_t LastSlash = ProcessName.find_last_of(L"\\");
                if (LastSlash != std::wstring::npos) {
                    ProcessName = ProcessName.substr(LastSlash + 1);
                }
                const wchar_t* Browsers[] = { L"msedge.exe", L"firefox.exe", L"vivaldi.exe", L"chrome.exe", L"brave.exe", L"browser.exe", L"opera.exe", L"waterfox.exe" };
                const int Size = sizeof(Browsers) / sizeof(Browsers[0]);
                for (int i = 0; i < Size; i++)
                {
                    if (ProcessName.rfind(Browsers[i], 0) == 0)
                    {
                        if (!AlreadyShown2)
                        {
                            if (ProgramName->c_str() != NULL)
                            {
                                std::wstring NotificationString(L"NoMoreCookies: The process ");
                                NotificationString.append(L"\"");
                                NotificationString.append(ProgramName->c_str());
                                NotificationString.append(L"\"");
                                NotificationString.append(L" tried to write to the browser memory, which has been denied successfully.");
                                ShowNotification(NotificationString);
                            }
                            else
                            {;
                                std::wstring NotificationString(L"NoMoreCookies: A Process tried to read the browser memory, which have been denied successfully.");
                                ShowNotification(NotificationString);
                            }
                            AlreadyShown2 = TRUE;
                        }
                        ReleaseMutex(Mutex6);
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
        }
    }
    ReleaseMutex(Mutex6);
    return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

BOOL AlreadyShown3 = FALSE;

NTSTATUS NTAPI HookedNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead)
{
    WaitForSingleObject(Mutex8, INFINITE);
    if (GetProcessId(ProcessHandle) != GetCurrentProcessId())
    {
        if (IsProcessSigned(ProcessHandle, XMode))
        {
            wchar_t ImageFileName[MAX_PATH + 1];
            if (GetProcessImageFileName(ProcessHandle, ImageFileName, MAX_PATH))
            {
                std::wstring ProcessName(ImageFileName);
                size_t LastSlash = ProcessName.find_last_of(L"\\");
                if (LastSlash != std::wstring::npos) {
                    ProcessName = ProcessName.substr(LastSlash + 1);
                }
                const wchar_t* Browsers[] = { L"msedge.exe", L"firefox.exe", L"vivaldi.exe", L"chrome.exe", L"brave.exe", L"browser.exe", L"opera.exe", L"waterfox.exe" };
                const int Size = sizeof(Browsers) / sizeof(Browsers[0]);
                for (int i = 0; i < Size; i++)
                {
                    if (ProcessName.rfind(Browsers[i], 0) == 0)
                    {
                        if (!AlreadyShown3)
                        {
                            if (ProgramName->c_str() != NULL)
                            {
                                std::wstring NotificationString(L"NoMoreCookies: The process ");
                                NotificationString.append(L"\"");
                                NotificationString.append(ProgramName->c_str());
                                NotificationString.append(L"\"");
                                NotificationString.append(L" tried to read the browser memory, which has been denied successfully.");
                                ShowNotification(NotificationString);
                            }
                            else
                            {
                                std::wstring NotificationString(L"NoMoreCookies: A Process tried to read the browser memory, which have been denied successfully.");
                                ShowNotification(NotificationString);
                            }
                            AlreadyShown3 = TRUE;
                        }
                        ReleaseMutex(Mutex8);
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
        }
    }
    ReleaseMutex(Mutex8);
    return OriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

void ForceExit()
{
    ExitProcess(0);
    //incase it didn't exit
    int* NullPointer = nullptr;
    *NullPointer = 42;
}

void VarsInitThread()
{
    NtCreateFileAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
    NtOpenFileAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile");
    NtResumeThreadAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeThread");
    NtSetValueKeyAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetValueKey");
    NtDeleteValueKeyAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDeleteValueKey");
    NtWriteVirtualMemoryAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
    NtProtectVirtualMemoryAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");
    NtReadVirtualMemoryAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadVirtualMemory");
    HMODULE Ntdll = GetModuleHandle(L"ntdll.dll");
    MODULEINFO Mi = { 0 };
    if (GetModuleInformation(GetCurrentProcess(), Ntdll, &Mi, sizeof(Mi)))
    {
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Mi.lpBaseOfDll;
        PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)Mi.lpBaseOfDll + DosHeader->e_lfanew);
        for (WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
        {
            PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(NtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
            if (!strcmp((char*)SectionHeader->Name, ".text"))
            {
                NtdllBaseAddress = (LPVOID)((DWORD_PTR)Mi.lpBaseOfDll + (DWORD_PTR)SectionHeader->VirtualAddress);
                break;
            }
        }
    }
    wchar_t ImageFileName[MAX_PATH + 1];
    if (GetProcessImageFileName(GetCurrentProcess(), ImageFileName, MAX_PATH))
    {
        std::wstring ProcessName(ImageFileName);
        size_t LastSlash = ProcessName.find_last_of(L"\\");
        if (LastSlash != std::wstring::npos) {
            ProcessName = ProcessName.substr(LastSlash + 1);
        }
        ProgramName->append(ProcessName);
    }
}

void CheckHook()
{
    BOOL CheckAll = FALSE;
    if (XMode && !Signed3)
        CheckAll = true;
    const char* Functions[] = { "NtCreateFile", "NtOpenFile", "NtResumeThread", "NtSetValueKey", "NtProtectVirtualMemory", "NtWriteVirtualMemory" };
    const char* FunctionsX[] = { "NtCreateFile", "NtOpenFile", "NtResumeThread", "NtSetValueKey", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtDeleteValueKey", "NtReadVirtualMemory"};
    const int Size = sizeof(Functions) / sizeof(Functions[0]);
    const int SizeX = sizeof(FunctionsX) / sizeof(FunctionsX[0]);
    DWORD SleepTime = 1000;
    if (XMode)
        SleepTime = 500;
    while (true)
    {
        Sleep(SleepTime);
        if (CheckAll)
        {
            for (int i = 0; i < SizeX; i++)
            {
                HMODULE Module = GetModuleHandleW(L"ntdll.dll");
                FARPROC FunctionAddress = GetProcAddress(Module, FunctionsX[i]);
                BYTE* StartAddressBytes = (BYTE*)FunctionAddress;
                if (StartAddressBytes[0] != 0xE9 || StartAddressBytes[0] == 0xCC)
                {
                    ForceExit();
                }
            }
        }
        else
        {
            for (int i = 0; i < Size; i++)
            {
                FARPROC FunctionAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), Functions[i]);
                BYTE* StartAddressBytes = (BYTE*)FunctionAddress;
                if (StartAddressBytes[0] != 0xE9 || StartAddressBytes[0] == 0xCC)
                {
                    ForceExit();
                }
            }
        }

        if (WatchThread)
        {
            DWORD ExitCode = 0;
            if (GetExitCodeThread(WatchingThread, &ExitCode))
            {
                if (ExitCode != STILL_ACTIVE)
                {
                    ForceExit();
                }
                ExitCode = 0;
            }
        }
    }
}

void ThreadWatcher()
{
    while (true)
    {
        Sleep(1000);
        DWORD ExitCode = 0;
        if (GetExitCodeThread(ProtectionThread, &ExitCode))
        {
            if (ExitCode != STILL_ACTIVE)
            {
                ForceExit();
            }
            ExitCode = 0;
        }
    }
}

void HookingThread()
{
    if (Startup())
    {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VarsInitThread, NULL, 0, NULL);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        OriginalNtCreateFile = reinterpret_cast<RealNtCreateFile>(DetourFindFunction("ntdll.dll", "NtCreateFile"));
        DetourAttach(&(LPVOID&)OriginalNtCreateFile, HookedNtCreateFile);
        OriginalNtOpenFile = reinterpret_cast<RealNtOpenFile>(DetourFindFunction("ntdll.dll", "NtOpenFile"));
        DetourAttach(&(LPVOID&)OriginalNtOpenFile, HookedNtOpenFile);
        if (!Mini)
        {
            OriginalNtResumeThread = reinterpret_cast<RealNtResumeThread>(DetourFindFunction("ntdll.dll", "NtResumeThread"));
            DetourAttach(&(LPVOID&)OriginalNtResumeThread, HookedNtResumeThread);
            OriginalNtSetValueKey = reinterpret_cast<RealNtSetValueKey>(DetourFindFunction("ntdll.dll", "NtSetValueKey"));
            DetourAttach(&(LPVOID&)OriginalNtSetValueKey, HookedNtSetValueKey);
            if (!Signed3 && !IsExplorer())
            {
                OriginalNtDeleteValueKey = reinterpret_cast<RealNtDeleteValueKey>(DetourFindFunction("ntdll.dll", "NtDeleteValueKey"));
                DetourAttach(&(LPVOID&)OriginalNtDeleteValueKey, HookedNtDeleteValueKey);
                OriginalNtReadVirtualMemory = reinterpret_cast<RealNtReadVirtualMemory>(DetourFindFunction("ntdll.dll", "NtReadVirtualMemory"));
                DetourAttach(&(LPVOID&)OriginalNtReadVirtualMemory, HookedNtReadVirtualMemory);
            }
            OriginalNtProtectVirtualMemory = reinterpret_cast<RealNtProtectVirtualMemory>(DetourFindFunction("ntdll.dll", "NtProtectVirtualMemory"));
            DetourAttach(&(LPVOID&)OriginalNtProtectVirtualMemory, HookedNtProtectVirtualMemory);
            OriginalNtWriteVirtualMemory = reinterpret_cast<RealNtWriteVirtualMemory>(DetourFindFunction("ntdll.dll", "NtWriteVirtualMemory"));
            DetourAttach(&(LPVOID&)OriginalNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
        }
        DetourTransactionCommit();
        if (!Mini)
        {
            ProtectionThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CheckHook, NULL, 0, NULL);
            if (ProtectionThread != NULL)
            {
                WatchingThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadWatcher, NULL, 0, NULL);
                if (WatchingThread != NULL)
                {
                    WatchThread = TRUE;
                }
            }
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
            if (!IsNoMoreCookiesInstaller(GetCurrentProcess()))
            {
                Signed = IsSigned(GetCurrentProcess(), XMode);
                Signed2 = IsSigned(GetCurrentProcess(), FALSE);
                BOOL IsAllowed = IsProcessAllowed();
                Signed3 = IsSigned(GetCurrentProcess(), FALSE) && IsAllowed;
                Module = hModule;
                if (!XMode)
                {
                    if ((!IsAllowed || !Signed2) && !IsRunningAsService())
                    {
                        HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HookingThread, NULL, NULL, NULL);
                        if (hThread != NULL)
                        {
                            CloseHandle(hThread);
                            return TRUE;
                        }
                    }
                }
                else
                {
                    if (!Signed && !IsRunningAsService())
                    {
                        HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HookingThread, NULL, NULL, NULL);
                        if (hThread != NULL)
                        {
                            CloseHandle(hThread);
                            return TRUE;
                        }
                    }
                }
            }
        }
    }
    return FALSE;
}