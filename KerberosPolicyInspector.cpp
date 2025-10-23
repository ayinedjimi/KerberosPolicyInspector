// KerberosPolicyInspector.cpp - Inspecteur de politiques Kerberos
// (c) 2025 Ayi NEDJIMI Consultants - Tous droits reserves
// Affiche politiques Kerberos du domaine (durees tickets, enctypes), recommandations

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_DCOM

#include <windows.h>
#include <commctrl.h>
#include <activeds.h>
#include <lm.h>
#include <winevt.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <memory>
#include <chrono>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")

// ======================== RAII AutoHandle ========================
class AutoHandle {
    HANDLE h;
public:
    explicit AutoHandle(HANDLE handle = INVALID_HANDLE_VALUE) : h(handle) {}
    ~AutoHandle() { if (h != INVALID_HANDLE_VALUE && h != NULL) CloseHandle(h); }
    operator HANDLE() const { return h; }
    HANDLE* operator&() { return &h; }
    AutoHandle(const AutoHandle&) = delete;
    AutoHandle& operator=(const AutoHandle&) = delete;
};

// ======================== Globals ========================
HWND g_hMainWnd = NULL;
HWND g_hListView = NULL;
HWND g_hStatusBar = NULL;
HWND g_hBtnQuery = NULL;
HWND g_hBtnExport = NULL;
HWND g_hBtnRecommendations = NULL;
HWND g_hProgressBar = NULL;

std::mutex g_logMutex;
std::wstring g_logFilePath;
bool g_scanning = false;

struct KerberosPolicy {
    std::wstring policyName;
    std::wstring currentValue;
    std::wstring recommendedValue;
    std::wstring securityLevel;
    std::wstring notes;
};

std::vector<KerberosPolicy> g_policies;

// ======================== Logging ========================
void InitLog() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    g_logFilePath = std::wstring(tempPath) + L"WinTools_KerberosPolicyInspector_log.txt";

    std::lock_guard<std::mutex> lock(g_logMutex);
    std::wofstream log(g_logFilePath, std::ios::app);
    log << L"\n========== KerberosPolicyInspector - " << std::chrono::system_clock::now().time_since_epoch().count() << L" ==========\n";
}

void Log(const std::wstring& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::wofstream log(g_logFilePath, std::ios::app);
    log << msg << L"\n";
}

// ======================== Utilities ========================
std::wstring GetCurrentTimeStamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

void SetStatus(const std::wstring& msg) {
    if (g_hStatusBar) {
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)msg.c_str());
    }
    Log(msg);
}

void ShowProgress(bool show) {
    if (g_hProgressBar) {
        ShowWindow(g_hProgressBar, show ? SW_SHOW : SW_HIDE);
        if (show) {
            SendMessageW(g_hProgressBar, PBM_SETMARQUEE, TRUE, 0);
        }
    }
}

void EnableButtons(bool enable) {
    EnableWindow(g_hBtnQuery, enable);
    EnableWindow(g_hBtnExport, enable);
    EnableWindow(g_hBtnRecommendations, enable);
}

// ======================== Domain Detection ========================
std::wstring GetDomainDN() {
    std::wstring dn;

    // Try to get domain from current machine
    LPWSTR domainName = NULL;
    NETSETUP_JOIN_STATUS joinStatus;

    if (NetGetJoinInformation(NULL, &domainName, &joinStatus) == NERR_Success) {
        if (joinStatus == NetSetupDomainName && domainName) {
            // Convert domain name to DN (e.g., "CORP" -> "DC=CORP,DC=LOCAL")
            std::wstring domain = domainName;
            dn = L"DC=";

            // Simple conversion: split by '.' and create DC= components
            size_t pos = 0;
            bool first = true;
            while ((pos = domain.find(L'.')) != std::wstring::npos) {
                if (!first) dn += L",DC=";
                dn += domain.substr(0, pos);
                domain.erase(0, pos + 1);
                first = false;
            }
            if (!domain.empty()) {
                if (!first) dn += L",DC=";
                dn += domain;
            }

            Log(L"Domain DN detecte: " + dn);
        }
        NetApiBufferFree(domainName);
    }

    return dn;
}

// ======================== Kerberos Policy Query (Registry) ========================
void QueryLocalKerberosPolicy() {
    // Query local Kerberos policy from registry
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value, size;

        // MaxTokenSize
        size = sizeof(value);
        if (RegQueryValueExW(hKey, L"MaxTokenSize", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            KerberosPolicy policy;
            policy.policyName = L"MaxTokenSize";
            policy.currentValue = std::to_wstring(value);
            policy.recommendedValue = L"48000";
            policy.securityLevel = (value >= 48000) ? L"OK" : L"Avertissement";
            policy.notes = L"Taille maximale du token Kerberos en octets";
            g_policies.push_back(policy);
        }

        RegCloseKey(hKey);
    }

    // Query encryption types
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value, size;

        size = sizeof(value);
        if (RegQueryValueExW(hKey, L"SupportedEncryptionTypes", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            KerberosPolicy policy;
            policy.policyName = L"SupportedEncryptionTypes";

            std::wstring enctypes;
            if (value & 0x1) enctypes += L"DES-CBC-CRC ";
            if (value & 0x2) enctypes += L"DES-CBC-MD5 ";
            if (value & 0x4) enctypes += L"RC4-HMAC ";
            if (value & 0x8) enctypes += L"AES128 ";
            if (value & 0x10) enctypes += L"AES256 ";

            policy.currentValue = enctypes;
            policy.recommendedValue = L"AES256 AES128";

            // Security check: DES or RC4 only
            if ((value & 0x3) && !(value & 0x18)) {
                policy.securityLevel = L"CRITIQUE";
                policy.notes = L"DES detecte - obsolete et faible!";
            } else if ((value & 0x4) && !(value & 0x18)) {
                policy.securityLevel = L"Avertissement";
                policy.notes = L"RC4 seul - migrer vers AES256";
            } else if (value & 0x18) {
                policy.securityLevel = L"OK";
                policy.notes = L"AES active";
            }

            g_policies.push_back(policy);
        }

        RegCloseKey(hKey);
    }
}

// ======================== Domain Policy Query (Simplified) ========================
void QueryDomainKerberosPolicy() {
    // Since querying domain GPO via LDAP requires complex ADSI parsing,
    // we'll query local effective policy which reflects domain policy

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Domain policies are often reflected here when applied via GPO

        DWORD value, size;

        // MaxTicketAge (hours)
        size = sizeof(value);
        if (RegQueryValueExW(hKey, L"MaxTicketAge", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            KerberosPolicy policy;
            policy.policyName = L"MaxTicketAge";
            policy.currentValue = std::to_wstring(value) + L" heures";
            policy.recommendedValue = L"10 heures";
            policy.securityLevel = (value <= 10) ? L"OK" : L"Avertissement";
            policy.notes = L"Duree de vie maximale du ticket TGT";
            g_policies.push_back(policy);
        }

        // MaxRenewAge (days)
        size = sizeof(value);
        if (RegQueryValueExW(hKey, L"MaxRenewAge", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            KerberosPolicy policy;
            policy.policyName = L"MaxRenewAge";
            policy.currentValue = std::to_wstring(value) + L" jours";
            policy.recommendedValue = L"7 jours";
            policy.securityLevel = (value <= 7) ? L"OK" : L"Avertissement";
            policy.notes = L"Duree maximale de renouvellement du ticket";
            g_policies.push_back(policy);
        }

        // MaxServiceAge (minutes)
        size = sizeof(value);
        if (RegQueryValueExW(hKey, L"MaxServiceAge", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            KerberosPolicy policy;
            policy.policyName = L"MaxServiceAge";
            policy.currentValue = std::to_wstring(value) + L" minutes";
            policy.recommendedValue = L"600 minutes";
            policy.securityLevel = (value <= 600) ? L"OK" : L"Info";
            policy.notes = L"Duree de vie du ticket de service";
            g_policies.push_back(policy);
        }

        // MaxClockSkew (minutes)
        size = sizeof(value);
        if (RegQueryValueExW(hKey, L"MaxClockSkew", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            KerberosPolicy policy;
            policy.policyName = L"MaxClockSkew";
            policy.currentValue = std::to_wstring(value) + L" minutes";
            policy.recommendedValue = L"5 minutes";
            policy.securityLevel = (value <= 5) ? L"OK" : L"Avertissement";
            policy.notes = L"Ecart d'horloge maximal autorise";
            g_policies.push_back(policy);
        }

        RegCloseKey(hKey);
    } else {
        // If no GPO applied, use default values
        KerberosPolicy policy;
        policy.policyName = L"Politique Domaine";
        policy.currentValue = L"Non configuree (defauts Windows)";
        policy.recommendedValue = L"Configurer via GPO";
        policy.securityLevel = L"Info";
        policy.notes = L"Utilisation des valeurs par defaut";
        g_policies.push_back(policy);
    }
}

// ======================== Event Log - Kerberos Errors ========================
void QueryKerberosEventLog() {
    const wchar_t* channelPath = L"System";
    const wchar_t* query = L"*[System[Provider[@Name='Microsoft-Windows-Security-Kerberos'] and (Level=2 or Level=3)]]";

    EVT_HANDLE hResults = EvtQuery(NULL, channelPath, query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hResults) {
        Log(L"Impossible d'interroger Event Log Kerberos");
        return;
    }

    EVT_HANDLE events[10];
    DWORD returned = 0;

    if (EvtNext(hResults, 10, events, INFINITE, 0, &returned)) {
        if (returned > 0) {
            KerberosPolicy policy;
            policy.policyName = L"Event Log Kerberos";
            policy.currentValue = std::to_wstring(returned) + L" erreur(s) recente(s)";
            policy.recommendedValue = L"0 erreurs";
            policy.securityLevel = L"Avertissement";
            policy.notes = L"Erreurs Kerberos detectees - verifier downgrades enctypes";
            g_policies.push_back(policy);

            Log(L"Erreurs Kerberos detectees: " + std::to_wstring(returned));
        }

        for (DWORD i = 0; i < returned; i++) {
            EvtClose(events[i]);
        }
    }

    EvtClose(hResults);
}

// ======================== Recommendations ========================
void ShowRecommendations() {
    std::wstringstream recommendations;
    recommendations << L"=== RECOMMANDATIONS SECURITE KERBEROS ===\n\n";

    recommendations << L"1. ENCRYPTION TYPES:\n";
    recommendations << L"   - Desactiver DES (obsolete, casse facilement)\n";
    recommendations << L"   - Minimiser RC4-HMAC (vulnerable a certaines attaques)\n";
    recommendations << L"   - Preferer AES256-HMAC-SHA1 (recommande)\n";
    recommendations << L"   - Commande: ksetup /setenctypeattr DOMAIN AES256-CTS-HMAC-SHA1-96\n\n";

    recommendations << L"2. DUREES DE TICKETS:\n";
    recommendations << L"   - MaxTicketAge: 10 heures max (defaut Windows: 10h)\n";
    recommendations << L"   - MaxRenewAge: 7 jours max (defaut Windows: 7j)\n";
    recommendations << L"   - MaxServiceAge: 600 minutes (defaut Windows: 600min)\n";
    recommendations << L"   - MaxClockSkew: 5 minutes (defaut Windows: 5min)\n\n";

    recommendations << L"3. HARDENING:\n";
    recommendations << L"   - Activer 'Audit Kerberos Service Ticket Operations'\n";
    recommendations << L"   - Configurer LDAP Signing (previent MITM)\n";
    recommendations << L"   - Utiliser Protected Users group pour comptes sensibles\n";
    recommendations << L"   - Deployer LAPS pour comptes administrateurs locaux\n\n";

    recommendations << L"4. MONITORING:\n";
    recommendations << L"   - Surveiller Event ID 4768 (TGT Request)\n";
    recommendations << L"   - Surveiller Event ID 4769 (Service Ticket Request)\n";
    recommendations << L"   - Alerter sur Event ID 4771 (Pre-auth failed)\n";
    recommendations << L"   - Detecter downgrades RC4/DES dans les logs\n\n";

    recommendations << L"5. COMPLIANCE:\n";
    recommendations << L"   - NIST 800-53: IA-5, SC-13 (Cryptographic Protection)\n";
    recommendations << L"   - CIS Benchmark: Section 2.3.11 (Kerberos Policy)\n";
    recommendations << L"   - PCI-DSS: Requirement 8.2.3 (Strong Cryptography)\n\n";

    recommendations << L"=== FIN RECOMMANDATIONS ===\n";

    MessageBoxW(g_hMainWnd, recommendations.str().c_str(), L"Recommandations Securite Kerberos", MB_ICONINFORMATION | MB_OK);
    Log(L"Recommandations affichees");
}

// ======================== ListView Management ========================
void InitListView() {
    ListView_DeleteAllItems(g_hListView);

    // Remove old columns
    while (ListView_DeleteColumn(g_hListView, 0));

    // Add columns
    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    lvc.fmt = LVCFMT_LEFT;

    lvc.cx = 180; lvc.pszText = const_cast<LPWSTR>(L"Politique");
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.cx = 200; lvc.pszText = const_cast<LPWSTR>(L"Valeur Actuelle");
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.cx = 150; lvc.pszText = const_cast<LPWSTR>(L"Recommandee");
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.cx = 100; lvc.pszText = const_cast<LPWSTR>(L"Securite");
    ListView_InsertColumn(g_hListView, 3, &lvc);

    lvc.cx = 350; lvc.pszText = const_cast<LPWSTR>(L"Notes");
    ListView_InsertColumn(g_hListView, 4, &lvc);
}

void UpdateListView() {
    ListView_DeleteAllItems(g_hListView);

    int idx = 0;
    for (const auto& policy : g_policies) {
        LVITEMW lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = idx;

        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(policy.policyName.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        ListView_SetItemText(g_hListView, idx, 1, const_cast<LPWSTR>(policy.currentValue.c_str()));
        ListView_SetItemText(g_hListView, idx, 2, const_cast<LPWSTR>(policy.recommendedValue.c_str()));
        ListView_SetItemText(g_hListView, idx, 3, const_cast<LPWSTR>(policy.securityLevel.c_str()));
        ListView_SetItemText(g_hListView, idx, 4, const_cast<LPWSTR>(policy.notes.c_str()));

        idx++;
    }
}

// ======================== Query Operations ========================
void PerformKerberosQuery() {
    g_scanning = true;
    EnableButtons(false);
    ShowProgress(true);
    SetStatus(L"Interrogation des politiques Kerberos...");

    g_policies.clear();

    // Detect domain
    std::wstring domainDN = GetDomainDN();
    if (!domainDN.empty()) {
        KerberosPolicy domainInfo;
        domainInfo.policyName = L"Domaine Detecte";
        domainInfo.currentValue = domainDN;
        domainInfo.securityLevel = L"Info";
        domainInfo.notes = L"Machine jointe au domaine";
        g_policies.push_back(domainInfo);
    } else {
        KerberosPolicy domainInfo;
        domainInfo.policyName = L"Domaine";
        domainInfo.currentValue = L"Standalone / Workgroup";
        domainInfo.securityLevel = L"Info";
        domainInfo.notes = L"Machine non jointe a un domaine";
        g_policies.push_back(domainInfo);
    }

    // Query local Kerberos policy
    QueryLocalKerberosPolicy();

    // Query domain policy (from effective GPO)
    QueryDomainKerberosPolicy();

    // Query Event Log for Kerberos errors
    QueryKerberosEventLog();

    UpdateListView();

    ShowProgress(false);
    EnableButtons(true);
    SetStatus(L"Interrogation terminee - " + std::to_wstring(g_policies.size()) + L" politiques analysees");
    g_scanning = false;
}

// ======================== Export CSV ========================
void ExportToCSV() {
    wchar_t filename[MAX_PATH] = L"KerberosPolicy_Report.csv";

    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"Fichiers CSV (*.csv)\0*.csv\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream csv(filename, std::ios::binary);
    if (!csv) {
        MessageBoxW(g_hMainWnd, L"Impossible de creer le fichier CSV", L"Erreur", MB_ICONERROR);
        return;
    }

    // UTF-8 BOM
    unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    csv.write(reinterpret_cast<wchar_t*>(bom), sizeof(bom) / sizeof(wchar_t));

    csv << L"Politique,ValeurActuelle,Recommandee,Securite,Notes\n";

    for (const auto& policy : g_policies) {
        csv << L"\"" << policy.policyName << L"\",";
        csv << L"\"" << policy.currentValue << L"\",";
        csv << L"\"" << policy.recommendedValue << L"\",";
        csv << L"\"" << policy.securityLevel << L"\",";
        csv << L"\"" << policy.notes << L"\"\n";
    }

    csv.close();

    std::wstring msg = L"Rapport exporte vers:\n" + std::wstring(filename);
    MessageBoxW(g_hMainWnd, msg.c_str(), L"Export reussi", MB_ICONINFORMATION);
    SetStatus(L"Export CSV termine");
}

// ======================== Window Procedure ========================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            InitLog();

            // ListView
            g_hListView = CreateWindowExW(
                0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                10, 10, 1160, 450,
                hwnd, (HMENU)1, GetModuleHandle(NULL), NULL
            );
            ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            InitListView();

            // Buttons
            g_hBtnQuery = CreateWindowExW(
                0, L"BUTTON", L"Interroger Domaine",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 470, 180, 30,
                hwnd, (HMENU)2, GetModuleHandle(NULL), NULL
            );

            g_hBtnExport = CreateWindowExW(
                0, L"BUTTON", L"Exporter Rapport",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                200, 470, 150, 30,
                hwnd, (HMENU)3, GetModuleHandle(NULL), NULL
            );

            g_hBtnRecommendations = CreateWindowExW(
                0, L"BUTTON", L"Afficher Recommandations",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                360, 470, 220, 30,
                hwnd, (HMENU)4, GetModuleHandle(NULL), NULL
            );

            // Progress bar
            g_hProgressBar = CreateWindowExW(
                0, PROGRESS_CLASSW, NULL,
                WS_CHILD | PBS_MARQUEE,
                590, 475, 200, 20,
                hwnd, (HMENU)5, GetModuleHandle(NULL), NULL
            );

            // Status bar
            g_hStatusBar = CreateWindowExW(
                0, STATUSCLASSNAMEW, NULL,
                WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                0, 0, 0, 0,
                hwnd, (HMENU)6, GetModuleHandle(NULL), NULL
            );

            SetStatus(L"Pret - Kerberos Policy Inspector (c) Ayi NEDJIMI Consultants");
            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case 2: // Query
                    std::thread(PerformKerberosQuery).detach();
                    break;

                case 3: // Export
                    ExportToCSV();
                    break;

                case 4: // Recommendations
                    ShowRecommendations();
                    break;
            }
            break;
        }

        case WM_SIZE: {
            RECT rc;
            GetClientRect(hwnd, &rc);

            SetWindowPos(g_hListView, NULL, 10, 10, rc.right - 20, rc.bottom - 100, SWP_NOZORDER);
            SetWindowPos(g_hBtnQuery, NULL, 10, rc.bottom - 80, 180, 30, SWP_NOZORDER);
            SetWindowPos(g_hBtnExport, NULL, 200, rc.bottom - 80, 150, 30, SWP_NOZORDER);
            SetWindowPos(g_hBtnRecommendations, NULL, 360, rc.bottom - 80, 220, 30, SWP_NOZORDER);
            SetWindowPos(g_hProgressBar, NULL, 590, rc.bottom - 75, 200, 20, SWP_NOZORDER);

            SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// ======================== Main ========================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialize COM
    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    // Initialize Common Controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    // Register window class
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"KerberosPolicyInspectorClass";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

    RegisterClassExW(&wc);

    // Create window
    g_hMainWnd = CreateWindowExW(
        0,
        L"KerberosPolicyInspectorClass",
        L"Kerberos Policy Inspector - (c) Ayi NEDJIMI Consultants",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1200, 600,
        NULL, NULL, hInstance, NULL
    );

    if (!g_hMainWnd) {
        CoUninitialize();
        return 1;
    }

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}
