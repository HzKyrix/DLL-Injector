// ================================================================
//  Kyrix Injector — standalone single-file C++ DLL Injector
//  Compile: cl /EHsc /W3 /O2 KyrixInjector.cpp
//           /link user32.lib kernel32.lib comdlg32.lib
//
//  Requires: Windows 7+, administrator privileges
// ================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <shlobj.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <conio.h>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")

// ----------------------------------------------------------------
//  Console color helpers
// ----------------------------------------------------------------
enum Color { GRAY = 8, WHITE = 15, CYAN = 11, GREEN = 10, RED = 12, YELLOW = 14, MAGENTA = 13 };

static void SetColor(Color c) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), (WORD)c);
}

static void Print(Color c, const char* fmt, ...) {
    SetColor(c);
    va_list args; va_start(args, fmt); vprintf(fmt, args); va_end(args);
    SetColor(GRAY);
}

// ----------------------------------------------------------------
//  NtCreateThreadEx typedef (resolved at runtime from ntdll)
// ----------------------------------------------------------------
typedef LONG(NTAPI* pNtCreateThreadEx_t)(
    PHANDLE   ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID     ObjectAttributes,
    HANDLE    ProcessHandle,
    PVOID     StartRoutine,
    PVOID     Argument,
    ULONG     CreateFlags,
    SIZE_T    ZeroBits,
    SIZE_T    StackSize,
    SIZE_T    MaximumStackSize,
    PVOID     AttributeList
    );

// ----------------------------------------------------------------
//  Process entry (foreground / taskbar-visible apps)
// ----------------------------------------------------------------
struct ProcessEntry {
    DWORD        pid;
    std::wstring exe;    // "notepad.exe"
    std::wstring title;  // "Untitled - Notepad"
};

// EnumWindows callback — collects taskbar-visible root windows
static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lp) {
    auto* list = reinterpret_cast<std::vector<ProcessEntry>*>(lp);

    if (!IsWindowVisible(hwnd))               return TRUE;
    if (GetWindowTextLengthW(hwnd) <= 0)      return TRUE;
    if (GetWindowLongW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) return TRUE;
    if (GetAncestor(hwnd, GA_ROOT) != hwnd)   return TRUE;

    wchar_t title[512] = {};
    GetWindowTextW(hwnd, title, 512);

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid) return TRUE;

    // Skip duplicates (same PID)
    for (const auto& e : *list)
        if (e.pid == pid) return TRUE;

    // Resolve exe name
    wchar_t path[MAX_PATH] = {};
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hp) {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(hp, 0, path, &sz);
        CloseHandle(hp);
    }

    std::wstring full(path);
    size_t slash = full.find_last_of(L"\\/");
    std::wstring fname = (slash != std::wstring::npos) ? full.substr(slash + 1) : full;
    if (fname.empty()) fname = L"unknown.exe";

    list->push_back({ pid, fname, std::wstring(title) });
    return TRUE;
}

static std::vector<ProcessEntry> GetForegroundProcesses() {
    std::vector<ProcessEntry> result;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&result));
    return result;
}

// ----------------------------------------------------------------
//  DLL Injection via NtCreateThreadEx + LoadLibraryW
// ----------------------------------------------------------------
struct InjectResult {
    bool        success;
    std::string error;
};

static InjectResult InjectDLL(DWORD pid, const wchar_t* dllPath) {

    // --- resolve NtCreateThreadEx at runtime (not in import table) ---
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return { false, "ntdll.dll not found" };

    auto pNtCreateThreadEx = (pNtCreateThreadEx_t)
        GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!pNtCreateThreadEx) return { false, "NtCreateThreadEx not found in ntdll" };

    // --- LoadLibraryW address ---
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) return { false, "kernel32.dll not found" };

    LPVOID pLoadLib = (LPVOID)GetProcAddress(hKernel, "LoadLibraryW");
    if (!pLoadLib) return { false, "LoadLibraryW not found" };

    // --- open target process ---
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        char buf[64]; snprintf(buf, sizeof(buf), "OpenProcess failed (err %lu)", GetLastError());
        return { false, buf };
    }

    // --- allocate memory in target for the DLL path ---
    SIZE_T pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemote = VirtualAllocEx(hProc, nullptr, pathBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) {
        DWORD e = GetLastError();
        CloseHandle(hProc);
        char buf[64]; snprintf(buf, sizeof(buf), "VirtualAllocEx failed (err %lu)", e);
        return { false, buf };
    }

    // --- write DLL path ---
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, pRemote, dllPath, pathBytes, &written)) {
        DWORD e = GetLastError();
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        char buf[64]; snprintf(buf, sizeof(buf), "WriteProcessMemory failed (err %lu)", e);
        return { false, buf };
    }

    // --- create remote thread via NtCreateThreadEx ---
    HANDLE hThread = nullptr;
    LONG status = pNtCreateThreadEx(
        &hThread,
        0x1FFFFF,    // THREAD_ALL_ACCESS
        nullptr,
        hProc,
        pLoadLib,    // start routine = LoadLibraryW
        pRemote,     // argument = DLL path in target memory
        0,           // not suspended
        0, 0, 0,
        nullptr
    );

    bool ok = (hThread != nullptr && status == 0);

    if (ok) {
        WaitForSingleObject(hThread, 8000);  // wait up to 8 s for DLL_PROCESS_ATTACH
    }

    // --- cleanup ---
    if (hThread) CloseHandle(hThread);
    VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (!ok) {
        char buf[80]; snprintf(buf, sizeof(buf), "NtCreateThreadEx failed (NTSTATUS 0x%08X)", (DWORD)status);
        return { false, buf };
    }
    return { true, "" };
}

// ----------------------------------------------------------------
//  File browse dialog (GetOpenFileName, *.dll filter)
// ----------------------------------------------------------------
static std::wstring BrowseDLL() {
    wchar_t path[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Kyrix Injector — Select DLL";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn)) return std::wstring(path);
    return L"";
}

// ----------------------------------------------------------------
//  Admin check
// ----------------------------------------------------------------
static bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te;
        DWORD sz = sizeof(te);
        if (GetTokenInformation(tok, TokenElevation, &te, sz, &sz))
            elevated = te.TokenIsElevated;
        CloseHandle(tok);
    }
    return elevated != FALSE;
}

// ----------------------------------------------------------------
//  wstring -> UTF-8 string for display
// ----------------------------------------------------------------
static std::string WtoA(const std::wstring& w) {
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(sz - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    return s;
}

// ----------------------------------------------------------------
//  Helpers for console UI
// ----------------------------------------------------------------
static void ClearConsole() { system("cls"); }
static void PrintSep() { Print(GRAY, "  %s\n", std::string(54, '-').c_str()); }

static void PrintBanner() {
    Print(WHITE, "\n");
    Print(WHITE, "   ██╗  ██╗██╗   ██╗██████╗ ██╗██╗  ██╗\n");
    Print(WHITE, "   ██║ ██╔╝╚██╗ ██╔╝██╔══██╗██║╚██╗██╔╝\n");
    Print(CYAN, "   █████╔╝  ╚████╔╝ ██████╔╝██║ ╚███╔╝ \n");
    Print(CYAN, "   ██╔═██╗   ╚██╔╝  ██╔══██╗██║ ██╔██╗ \n");
    Print(WHITE, "   ██║  ██╗   ██║   ██║  ██║██║██╔╝ ██╗\n");
    Print(WHITE, "   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝\n");
    Print(GRAY, "        I N J E C T O R   v1.0\n\n");
    PrintSep();
}

// ================================================================
//  MAIN
// ================================================================
int main() {
    // Setup console
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleA("Kyrix Injector");

    // Enable ANSI / virtual terminal sequences
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    ClearConsole();
    PrintBanner();

    // --- admin check ---
    if (!IsElevated()) {
        Print(RED, "  [!] Administrator privileges required.\n");
        Print(RED, "      Please re-run as Administrator.\n\n");
        system("pause");
        return 1;
    }
    Print(GREEN, "  [+] Running as Administrator\n");
    PrintSep();

    // ============================================================
    //  STEP 1 — Select Process
    // ============================================================
    std::vector<ProcessEntry> procs;
    int selProc = -1;

step_process:
    ClearConsole();
    PrintBanner();

    Print(WHITE, "  [ SELECT PROCESS ]\n");
    Print(GRAY, "  Listing foreground applications...\n\n");

    procs = GetForegroundProcesses();

    if (procs.empty()) {
        Print(YELLOW, "  [!] No foreground applications found.\n");
        Print(GRAY, "  Press any key to retry...\n");
        _getch();
        goto step_process;
    }

    for (int i = 0; i < (int)procs.size(); ++i) {
        std::string exe = WtoA(procs[i].exe);
        std::string title = WtoA(procs[i].title);
        if (title.size() > 35) title = title.substr(0, 35) + "...";

        Print(CYAN, "  [%2d]", i + 1);
        Print(WHITE, "  %-28s", exe.c_str());
        Print(GRAY, "  %s  ", title.c_str());
        Print(GRAY, "(PID: %lu)\n", procs[i].pid);
    }

    PrintSep();
    Print(GRAY, "   R  = Refresh list\n");
    Print(GRAY, "   Q  = Quit\n");
    PrintSep();
    Print(WHITE, "  Enter number: ");

    {
        char input[32] = {};
        fgets(input, sizeof(input), stdin);
        if (input[0] == 'r' || input[0] == 'R') goto step_process;
        if (input[0] == 'q' || input[0] == 'Q') return 0;

        int n = atoi(input);
        if (n < 1 || n >(int)procs.size()) {
            Print(RED, "  [!] Invalid selection.\n");
            Sleep(1000);
            goto step_process;
        }
        selProc = n - 1;
    }

    // ============================================================
    //  STEP 2 — Select DLL
    // ============================================================
    {
        ClearConsole();
        PrintBanner();

        Print(WHITE, "  [ SELECT DLL ]\n\n");
        Print(GREEN, "  Target  : %s (PID %lu)\n",
            WtoA(procs[selProc].exe).c_str(), procs[selProc].pid);
        PrintSep();
        Print(WHITE, "\n  Options:\n");
        Print(CYAN, "   1"); Print(GRAY, " — Browse for DLL (file dialog)\n");
        Print(CYAN, "   2"); Print(GRAY, " — Type path manually\n");
        Print(GRAY, "   B"); Print(GRAY, " — Back to process list\n");
        Print(GRAY, "   Q"); Print(GRAY, " — Quit\n");
        PrintSep();
        Print(WHITE, "  Choice: ");

        char choice[8] = {};
        fgets(choice, sizeof(choice), stdin);

        std::wstring dllPath;

        if (choice[0] == '1') {
            // File dialog
            Print(GRAY, "\n  Opening file dialog...\n");
            dllPath = BrowseDLL();
            if (dllPath.empty()) {
                Print(YELLOW, "  [!] No file selected.\n");
                Sleep(1200);
                goto step_process;
            }
        }
        else if (choice[0] == '2') {
            Print(WHITE, "\n  Enter full DLL path: ");
            char pathbuf[MAX_PATH] = {};
            fgets(pathbuf, sizeof(pathbuf), stdin);
            // strip newline
            size_t len = strlen(pathbuf);
            if (len > 0 && (pathbuf[len - 1] == '\n' || pathbuf[len - 1] == '\r'))
                pathbuf[len - 1] = '\0';
            // strip surrounding quotes
            std::string raw(pathbuf);
            if (!raw.empty() && raw.front() == '"') raw = raw.substr(1);
            if (!raw.empty() && raw.back() == '"') raw.pop_back();

            int wsz = MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), -1, nullptr, 0);
            dllPath.resize(wsz - 1);
            MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), -1, &dllPath[0], wsz);

            if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                Print(RED, "\n  [!] File not found: %s\n", raw.c_str());
                Sleep(1500);
                goto step_process;
            }
        }
        else if (choice[0] == 'b' || choice[0] == 'B') {
            goto step_process;
        }
        else if (choice[0] == 'q' || choice[0] == 'Q') {
            return 0;
        }
        else {
            Print(RED, "  [!] Invalid choice.\n");
            Sleep(800);
            goto step_process;
        }

        // ========================================================
        //  STEP 3 — Confirm + Inject
        // ========================================================
        ClearConsole();
        PrintBanner();

        Print(WHITE, "  [ INJECT SUMMARY ]\n\n");
        Print(GRAY, "  Process : ");
        Print(WHITE, "%s", WtoA(procs[selProc].exe).c_str());
        Print(GRAY, "  (PID %lu)\n", procs[selProc].pid);
        Print(GRAY, "  DLL     : ");

        // show just filename
        size_t sl = dllPath.find_last_of(L"\\/");
        std::wstring fname = (sl != std::wstring::npos) ? dllPath.substr(sl + 1) : dllPath;
        Print(WHITE, "%s\n", WtoA(fname).c_str());
        Print(GRAY, "  Method  : NtCreateThreadEx + LoadLibraryW\n\n");
        PrintSep();
        Print(WHITE, "  Press ENTER to inject, or Q to cancel: ");

        char confirm[8] = {};
        fgets(confirm, sizeof(confirm), stdin);
        if (confirm[0] == 'q' || confirm[0] == 'Q') goto step_process;

        // --- do inject ---
        Print(YELLOW, "\n  [~] Injecting...\n");

        InjectResult res = InjectDLL(procs[selProc].pid, dllPath.c_str());

        PrintSep();
        if (res.success) {
            Print(GREEN, "\n  [+] INJECTION SUCCESSFUL!\n");
            Print(GREEN, "      %s -> %s\n\n",
                WtoA(fname).c_str(),
                WtoA(procs[selProc].exe).c_str());
        }
        else {
            Print(RED, "\n  [!] INJECTION FAILED\n");
            Print(RED, "      %s\n\n", res.error.c_str());
        }
        PrintSep();

        Print(GRAY, "\n  Options:\n");
        Print(CYAN, "   1"); Print(GRAY, " — Inject again (same process/DLL)\n");
        Print(CYAN, "   2"); Print(GRAY, " — Choose new process\n");
        Print(CYAN, "   Q"); Print(GRAY, " — Quit\n");
        PrintSep();
        Print(WHITE, "  Choice: ");

        char after[8] = {};
        fgets(after, sizeof(after), stdin);
        if (after[0] == '1') {
            // repeat inject
            Print(YELLOW, "\n  [~] Re-injecting...\n");
            res = InjectDLL(procs[selProc].pid, dllPath.c_str());
            if (res.success)
                Print(GREEN, "  [+] Success!\n");
            else
                Print(RED, "  [!] Failed: %s\n", res.error.c_str());
            Sleep(1500);
        }
        if (after[0] == 'q' || after[0] == 'Q') return 0;
    }

    goto step_process;
}
