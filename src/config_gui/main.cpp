#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <CommCtrl.h>
#include <Shellapi.h>
#include <ShObjIdl.h>
#include <TlHelp32.h>
#include <dwmapi.h>
#include <uxtheme.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "config.hpp"
#include "rivet_parser.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr INT_PTR IDC_LIST        = 101;
constexpr INT_PTR IDC_DETAIL      = 102;
constexpr INT_PTR IDC_CHK_CONSOLE = 103;
constexpr INT_PTR IDC_BTN_ALL     = 104;
constexpr INT_PTR IDC_BTN_NONE    = 105;
constexpr INT_PTR IDC_BTN_SAVE    = 106;
constexpr INT_PTR IDC_BTN_LAUNCH  = 107;
constexpr INT_PTR IDC_STATUS      = 108;
constexpr INT_PTR IDC_HEADER      = 109;
constexpr INT_PTR IDC_LBL_GAME    = 110;
constexpr INT_PTR IDC_EDIT_GAME   = 111;
constexpr INT_PTR IDC_BTN_BROWSE  = 112;
constexpr INT_PTR IDC_BTN_INSTALL = 113;
constexpr INT_PTR IDC_BTN_UNINST  = 114;

struct PatchItem {
    std::string name;
    std::string display_name;
    std::string description;
    std::string author;
    std::string filename;
    std::vector<std::string> required_manifests;
    size_t site_count = 0;
    bool manifest_enabled = true;
    bool checked = true;
};

constexpr COLORREF CLR_BG        = RGB(28, 28, 30);
constexpr COLORREF CLR_SURFACE   = RGB(37, 37, 40);
constexpr COLORREF CLR_HEADER_BG = RGB(45, 45, 48);
constexpr COLORREF CLR_BORDER    = RGB(62, 62, 66);
constexpr COLORREF CLR_TEXT      = RGB(232, 232, 232);
constexpr COLORREF CLR_MUTED     = RGB(175, 175, 180);

struct AppState {
    std::filesystem::path exe_dir;     // Directory containing GlitchConfig.exe
    std::filesystem::path game_dir;    // Detected or user-chosen game install directory
    std::filesystem::path active_dir;  // Where config/patches are currently read from (game_dir if installed, else exe_dir)
    std::filesystem::path config_path;
    std::filesystem::path patches_dir;
    riftloader::LoaderConfig config;
    std::vector<PatchItem> items;
    std::unordered_map<std::string, size_t> name_to_idx;

    HWND hwnd = nullptr;
    HWND hLblGame = nullptr;
    HWND hEditGame = nullptr;
    HWND hBtnBrowse = nullptr;
    HWND hBtnInstall = nullptr;
    HWND hBtnUninst = nullptr;
    HWND hHeader = nullptr;
    HWND hList = nullptr;
    HWND hListHeader = nullptr;
    HWND hDetail = nullptr;
    HWND hChkConsole = nullptr;
    HWND hBtnAll = nullptr;
    HWND hBtnNone = nullptr;
    HWND hBtnSave = nullptr;
    HWND hBtnLaunch = nullptr;
    HWND hStatus = nullptr;
    HFONT hFont = nullptr;
    HBRUSH hBrushBg = nullptr;
    HBRUSH hBrushSurface = nullptr;

    bool updating = false;
    bool dirty = false;
};

AppState g_app;

void EnableDarkModeApp() {
    HMODULE hUx = LoadLibraryExW(L"uxtheme.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hUx) return;
    using SetPreferredAppModeFn = int(WINAPI*)(int);
    auto fn = reinterpret_cast<SetPreferredAppModeFn>(GetProcAddress(hUx, MAKEINTRESOURCEA(135)));
    if (fn) {
        fn(2); // ForceDark
    }
}

void ApplyDarkTitleBar(HWND hwnd) {
    BOOL dark = TRUE;
    constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_20 = 20;
    constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_19 = 19;
    if (FAILED(DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_20, &dark, sizeof(dark)))) {
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_19, &dark, sizeof(dark));
    }
}

LRESULT CALLBACK ListViewDarkHeaderProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                        UINT_PTR, DWORD_PTR) {
    if (msg == WM_NOTIFY) {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->hwndFrom == g_app.hListHeader && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<LPNMCUSTOMDRAW>(lParam);
            if (cd->dwDrawStage == CDDS_PREPAINT) {
                return CDRF_NOTIFYITEMDRAW;
            }
            if (cd->dwDrawStage == CDDS_ITEMPREPAINT) {
                SetTextColor(cd->hdc, CLR_TEXT);
                SetBkColor(cd->hdc, CLR_HEADER_BG);
                HBRUSH hbr = CreateSolidBrush(CLR_HEADER_BG);
                FillRect(cd->hdc, &cd->rc, hbr);
                DeleteObject(hbr);

                HPEN hpen = CreatePen(PS_SOLID, 1, CLR_BORDER);
                HGDIOBJ old = SelectObject(cd->hdc, hpen);
                MoveToEx(cd->hdc, cd->rc.right - 1, cd->rc.top, nullptr);
                LineTo(cd->hdc, cd->rc.right - 1, cd->rc.bottom);
                MoveToEx(cd->hdc, cd->rc.left, cd->rc.bottom - 1, nullptr);
                LineTo(cd->hdc, cd->rc.right, cd->rc.bottom - 1);
                SelectObject(cd->hdc, old);
                DeleteObject(hpen);

                wchar_t buf[128] = {};
                HDITEMW hdi = {};
                hdi.mask = HDI_TEXT;
                hdi.pszText = buf;
                hdi.cchTextMax = 128;
                Header_GetItem(g_app.hListHeader, static_cast<int>(cd->dwItemSpec), &hdi);

                RECT trc = cd->rc;
                trc.left += 6;
                trc.right -= 4;
                SetBkMode(cd->hdc, TRANSPARENT);
                DrawTextW(cd->hdc, buf, -1, &trc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                return CDRF_SKIPDEFAULT;
            }
        }
    }
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

bool PathsEqual(const std::filesystem::path& a, const std::filesystem::path& b) {
    if (a.empty() || b.empty()) return false;
    std::error_code ec;
    if (std::filesystem::equivalent(a, b, ec)) return true;
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

bool IsValidGameDir(const std::filesystem::path& dir) {
    if (dir.empty()) return false;
    std::error_code ec;
    return std::filesystem::is_regular_file(dir / "RiftApart.exe", ec);
}

struct ExeVersion {
    WORD major = 0, minor = 0, build = 0, rev = 0;
    bool valid = false;

    bool MatchesExpected() const {
        return valid && major == 3 && minor == 630 && build == 1 && rev == 0;
    }

    std::wstring ToString() const {
        if (!valid) return L"unknown";
        return std::to_wstring(major) + L"." + std::to_wstring(minor) + L"." +
               std::to_wstring(build) + L"." + std::to_wstring(rev);
    }
};

ExeVersion ReadExeFileVersion(const std::filesystem::path& exe_path) {
    ExeVersion out;
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(exe_path.c_str(), &handle);
    if (size == 0) return out;

    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(exe_path.c_str(), 0, size, buf.data())) return out;

    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    if (VerQueryValueW(buf.data(), L"\\", reinterpret_cast<LPVOID*>(&ffi), &len) &&
        ffi && len >= sizeof(VS_FIXEDFILEINFO)) {
        out.major = HIWORD(ffi->dwFileVersionMS);
        out.minor = LOWORD(ffi->dwFileVersionMS);
        out.build = HIWORD(ffi->dwFileVersionLS);
        out.rev   = LOWORD(ffi->dwFileVersionLS);
        out.valid = true;
    }
    return out;
}

bool IsGlitchInstalledIn(const std::filesystem::path& dir) {
    if (!IsValidGameDir(dir)) return false;
    std::error_code ec;
    return std::filesystem::is_regular_file(dir / "winmm.dll", ec) &&
           std::filesystem::is_regular_file(dir / "Glitch.dll", ec);
}

bool HasInstallPayloadIn(const std::filesystem::path& dir) {
    std::error_code ec;
    return std::filesystem::is_regular_file(dir / "winmm.dll", ec) &&
           std::filesystem::is_regular_file(dir / "Glitch.dll", ec) &&
           std::filesystem::is_directory(dir / "glitch" / "patches", ec);
}

std::wstring ReadRegistryString(HKEY root, const wchar_t* subkey, const wchar_t* value_name) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return {};
    wchar_t buf[1024] = {};
    DWORD bytes = sizeof(buf) - sizeof(wchar_t);
    DWORD type = 0;
    std::wstring res;
    if (RegQueryValueExW(hKey, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &bytes) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        res = buf;
    }
    RegCloseKey(hKey);
    return res;
}

std::vector<std::filesystem::path> ParseSteamLibraryFolders(const std::filesystem::path& steam_root) {
    std::vector<std::filesystem::path> libs;
    libs.push_back(steam_root);

    std::ifstream f(steam_root / "steamapps" / "libraryfolders.vdf");
    if (!f) return libs;

    std::string line;
    while (std::getline(f, line)) {
        // Match lines like: "path"    "D:\\SteamLibrary"
        size_t q1 = line.find('"');
        if (q1 == std::string::npos) continue;
        size_t q2 = line.find('"', q1 + 1);
        if (q2 == std::string::npos) continue;
        std::string key = line.substr(q1 + 1, q2 - q1 - 1);
        if (key != "path") continue;

        size_t q3 = line.find('"', q2 + 1);
        if (q3 == std::string::npos) continue;
        size_t q4 = line.find('"', q3 + 1);
        if (q4 == std::string::npos) continue;
        std::string raw = line.substr(q3 + 1, q4 - q3 - 1);

        std::string unescaped;
        unescaped.reserve(raw.size());
        for (size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == '\\' && i + 1 < raw.size() && raw[i + 1] == '\\') {
                unescaped.push_back('\\');
                ++i;
            } else {
                unescaped.push_back(raw[i]);
            }
        }
        if (!unescaped.empty()) {
            libs.emplace_back(Utf8ToWide(unescaped));
        }
    }
    return libs;
}

std::filesystem::path DetectGameDir(const std::filesystem::path& exe_dir) {
    if (IsValidGameDir(exe_dir)) {
        return exe_dir;
    }

    std::vector<std::filesystem::path> steam_roots;
    auto add_root = [&](const std::wstring& s) {
        if (!s.empty()) steam_roots.emplace_back(s);
    };
    add_root(ReadRegistryString(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath"));
    add_root(ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Valve\\Steam", L"InstallPath"));
    add_root(ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Valve\\Steam", L"InstallPath"));

    for (const auto& root : steam_roots) {
        for (const auto& lib : ParseSteamLibraryFolders(root)) {
            std::filesystem::path candidate = lib / "steamapps" / "common" / "Ratchet & Clank - Rift Apart";
            if (IsValidGameDir(candidate)) {
                return candidate;
            }
        }
    }

    const wchar_t* fallbacks[] = {
        L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\Ratchet & Clank - Rift Apart",
        L"C:\\Program Files\\Epic Games\\RatchetAndClankRiftApart",
    };
    for (const wchar_t* fb : fallbacks) {
        std::filesystem::path p(fb);
        if (IsValidGameDir(p)) return p;
    }
    return {};
}

bool BrowseForGameDir(HWND owner, std::filesystem::path& out_dir) {
    IFileOpenDialog* dlg = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg));
    if (FAILED(hr) || !dlg) return false;

    DWORD opts = 0;
    dlg->GetOptions(&opts);
    dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dlg->SetTitle(L"Select Ratchet & Clank: Rift Apart Install Folder");

    bool ok = false;
    if (SUCCEEDED(dlg->Show(owner))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item)) && item) {
            PWSTR psz = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &psz)) && psz) {
                out_dir = std::filesystem::path(psz);
                CoTaskMemFree(psz);
                ok = true;
            }
            item->Release();
        }
    }
    dlg->Release();
    return ok;
}

void OfferElevationAndRestart(const wchar_t* action_desc) {
    std::wstring msg = L"Permission denied while trying to " + std::wstring(action_desc) +
                       L" in:\n" + g_app.game_dir.wstring() +
                       L"\n\nRestart GlitchConfig as Administrator?";
    if (MessageBoxW(g_app.hwnd, msg.c_str(), L"Glitch", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        wchar_t self_exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, self_exe, MAX_PATH);
        HINSTANCE r = ShellExecuteW(
            g_app.hwnd, L"runas", self_exe, nullptr, g_app.exe_dir.c_str(), SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(r) > 32) {
            PostQuitMessage(0);
        }
    }
}

void SetStatusText(const std::wstring& text) {
    if (g_app.hStatus) {
        SetWindowTextW(g_app.hStatus, text.c_str());
    }
}

void UpdateCountStatus() {
    size_t enabled_cnt = 0;
    for (const auto& it : g_app.items) {
        if (it.checked) ++enabled_cnt;
    }
    std::wstring msg = std::to_wstring(enabled_cnt) + L" / " +
                       std::to_wstring(g_app.items.size()) + L" patches enabled";
    if (g_app.dirty) msg += L" (unsaved)";
    SetStatusText(msg);
}

std::string DisplayNameFor(const std::string& internal_name) {
    auto it = g_app.name_to_idx.find(internal_name);
    if (it != g_app.name_to_idx.end()) {
        return g_app.items[it->second].display_name;
    }
    return internal_name;
}

std::string JoinDisplayNames(const std::vector<std::string>& internal_names, const char* sep) {
    std::string out;
    for (size_t i = 0; i < internal_names.size(); ++i) {
        if (i > 0) out += sep;
        out += DisplayNameFor(internal_names[i]);
    }
    return out;
}

void UpdateDetailForSelection() {
    int sel = ListView_GetNextItem(g_app.hList, -1, LVNI_SELECTED);
    if (sel < 0 || static_cast<size_t>(sel) >= g_app.items.size()) {
        SetWindowTextW(g_app.hDetail, L"Select a patch above to view details.");
        return;
    }
    const auto& it = g_app.items[static_cast<size_t>(sel)];
    std::string text = it.display_name + "\r\n";
    if (!it.description.empty()) {
        text += it.description + "\r\n";
    }
    if (!it.required_manifests.empty()) {
        text += "Requires: " + JoinDisplayNames(it.required_manifests, ", ") + "\r\n";
    }
    SetWindowTextW(g_app.hDetail, Utf8ToWide(text).c_str());
}

void SyncListViewCheckmarks() {
    g_app.updating = true;
    for (size_t i = 0; i < g_app.items.size(); ++i) {
        BOOL cur = ListView_GetCheckState(g_app.hList, static_cast<int>(i));
        BOOL want = g_app.items[i].checked ? TRUE : FALSE;
        if (cur != want) {
            ListView_SetCheckState(g_app.hList, static_cast<int>(i), want);
        }
    }
    g_app.updating = false;
}

void OnItemToggled(size_t idx, bool now_checked) {
    if (idx >= g_app.items.size()) return;
    g_app.items[idx].checked = now_checked;
    g_app.dirty = true;

    std::vector<std::string> auto_changed;

    if (now_checked) {
        std::vector<size_t> stack = {idx};
        while (!stack.empty()) {
            size_t cur = stack.back();
            stack.pop_back();
            for (const auto& req : g_app.items[cur].required_manifests) {
                auto it = g_app.name_to_idx.find(req);
                if (it != g_app.name_to_idx.end() && !g_app.items[it->second].checked) {
                    g_app.items[it->second].checked = true;
                    auto_changed.push_back(req);
                    stack.push_back(it->second);
                }
            }
        }
    } else {
        bool progress = true;
        while (progress) {
            progress = false;
            for (size_t i = 0; i < g_app.items.size(); ++i) {
                if (!g_app.items[i].checked) continue;
                for (const auto& req : g_app.items[i].required_manifests) {
                    auto it = g_app.name_to_idx.find(req);
                    if (it != g_app.name_to_idx.end() && !g_app.items[it->second].checked) {
                        g_app.items[i].checked = false;
                        auto_changed.push_back(g_app.items[i].name);
                        progress = true;
                        break;
                    }
                }
            }
        }
    }

    SyncListViewCheckmarks();

    if (!auto_changed.empty()) {
        std::string verb = now_checked ? "Auto-enabled required: " : "Auto-disabled dependent: ";
        SetStatusText(Utf8ToWide(verb + JoinDisplayNames(auto_changed, ", ")));
    } else {
        UpdateCountStatus();
    }
}

void UpdateInstallButtons() {
    const bool valid_game = IsValidGameDir(g_app.game_dir);
    const bool installed = IsGlitchInstalledIn(g_app.game_dir);
    const bool running_from_game = valid_game && PathsEqual(g_app.exe_dir, g_app.game_dir);
    const bool has_payload = HasInstallPayloadIn(g_app.exe_dir);

    if (valid_game) {
        ExeVersion ver = ReadExeFileVersion(g_app.game_dir / "RiftApart.exe");
        std::wstring display = g_app.game_dir.wstring();
        if (ver.valid) {
            display += L"  (v" + ver.ToString();
            if (!ver.MatchesExpected()) {
                display += L" - UNSUPPORTED, expected v3.630.1.0";
            }
            display += L")";
        }
        SetWindowTextW(g_app.hEditGame, display.c_str());
    } else {
        SetWindowTextW(g_app.hEditGame, L"Not found - click Browse to locate RiftApart.exe");
    }

    if (running_from_game) {
        SetWindowTextW(g_app.hBtnInstall, L"Installed");
        EnableWindow(g_app.hBtnInstall, FALSE);
    } else if (installed) {
        SetWindowTextW(g_app.hBtnInstall, L"Reinstall");
        EnableWindow(g_app.hBtnInstall, (valid_game && has_payload) ? TRUE : FALSE);
    } else {
        SetWindowTextW(g_app.hBtnInstall, L"Install");
        EnableWindow(g_app.hBtnInstall, (valid_game && has_payload) ? TRUE : FALSE);
    }

    EnableWindow(g_app.hBtnUninst, installed ? TRUE : FALSE);
    EnableWindow(g_app.hBtnLaunch, valid_game ? TRUE : FALSE);
}

void LoadPatchListFromActiveDir() {
    if (IsGlitchInstalledIn(g_app.game_dir)) {
        g_app.active_dir = g_app.game_dir;
    } else {
        g_app.active_dir = g_app.exe_dir;
    }
    g_app.config_path = g_app.active_dir / "glitch" / "config.rvt";

    std::string warn;
    g_app.config = riftloader::LoaderConfig::LoadOrDefault(g_app.config_path.string(), &warn);

    std::filesystem::path pdir(g_app.config.patches_dir);
    g_app.patches_dir = pdir.is_absolute() ? pdir : (g_app.active_dir / pdir);

    g_app.items.clear();
    g_app.name_to_idx.clear();

    namespace fs = std::filesystem;
    std::error_code ec;
    std::vector<fs::path> files;
    if (fs::exists(g_app.patches_dir, ec)) {
        for (const auto& entry : fs::directory_iterator(g_app.patches_dir, ec)) {
            if (entry.is_regular_file() && entry.path().extension() == ".rvt") {
                files.push_back(entry.path());
            }
        }
    }
    std::sort(files.begin(), files.end());

    for (const auto& f : files) {
        auto parsed = riftloader::RivetParser::ParseFile(f.string());
        if (!parsed.Ok()) continue;
        const auto* r = parsed.root.get();

        PatchItem item;
        item.filename = f.filename().string();
        item.name = r->GetString("name", f.stem().string());
        item.display_name = r->GetString("display_name", item.name);
        item.description = r->GetString("description", r->GetString("why", ""));
        item.author = r->GetString("author", "");
        item.manifest_enabled = r->GetBool("enabled", true);

        if (const auto* arr = r->Get("patches")) {
            item.site_count = arr->ordered_children.size();
        } else if (r->Get("site")) {
            item.site_count = 1;
        }
        if (const auto* rm = r->Get("required_manifests")) {
            for (const auto& c : rm->ordered_children) {
                if (!c->raw_value.empty()) item.required_manifests.push_back(c->raw_value);
            }
        }

        item.checked = item.manifest_enabled && !g_app.config.disabled_patches.count(item.name);
        g_app.name_to_idx[item.name] = g_app.items.size();
        g_app.items.push_back(std::move(item));
    }

    g_app.dirty = false;
}

void PopulateListView() {
    g_app.updating = true;
    ListView_DeleteAllItems(g_app.hList);

    for (size_t i = 0; i < g_app.items.size(); ++i) {
        const auto& it = g_app.items[i];
        std::wstring wname = Utf8ToWide(it.display_name);
        std::wstring wreqs = Utf8ToWide(JoinDisplayNames(it.required_manifests, ", "));
        std::wstring wdesc = Utf8ToWide(it.description);

        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = static_cast<int>(i);
        lvi.pszText = wname.data();
        ListView_InsertItem(g_app.hList, &lvi);

        ListView_SetItemText(g_app.hList, static_cast<int>(i), 1, wreqs.data());
        ListView_SetItemText(g_app.hList, static_cast<int>(i), 2, wdesc.data());
        ListView_SetCheckState(g_app.hList, static_cast<int>(i), it.checked ? TRUE : FALSE);
    }

    g_app.updating = false;
    SendMessageW(g_app.hChkConsole, BM_SETCHECK,
                 g_app.config.console ? BST_CHECKED : BST_UNCHECKED, 0);
    UpdateCountStatus();
    if (!g_app.items.empty()) {
        ListView_SetItemState(g_app.hList, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    UpdateDetailForSelection();
    UpdateInstallButtons();
}

bool SaveConfigTo(const std::filesystem::path& target_cfg) {
    g_app.config.console = (SendMessageW(g_app.hChkConsole, BM_GETCHECK, 0, 0) == BST_CHECKED);
    g_app.config.disabled_patches.clear();
    for (const auto& it : g_app.items) {
        if (!it.checked) {
            g_app.config.disabled_patches.insert(it.name);
        }
    }

    if (!g_app.config.Save(target_cfg.string())) {
        OfferElevationAndRestart(L"save glitch\\config.rvt");
        return false;
    }

    g_app.dirty = false;
    SetStatusText(L"Saved to glitch\\config.rvt");
    return true;
}

bool IsProcessRunning(const wchar_t* exe_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe_name) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

void HandleFsError(const std::error_code& ec, const wchar_t* action_desc) {
    if (ec.value() == ERROR_SHARING_VIOLATION || ec.value() == ERROR_LOCK_VIOLATION) {
        std::wstring msg = L"A file is currently in use while trying to " + std::wstring(action_desc) +
                           L".\n\nClose RiftApart.exe and any other GlitchConfig window, then try again.";
        MessageBoxW(g_app.hwnd, msg.c_str(), L"Glitch - File In Use", MB_OK | MB_ICONWARNING);
        return;
    }
    OfferElevationAndRestart(action_desc);
}

bool InstallToGameDir() {
    namespace fs = std::filesystem;
    if (IsProcessRunning(L"RiftApart.exe")) {
        MessageBoxW(g_app.hwnd,
                    L"Ratchet & Clank: Rift Apart (RiftApart.exe) is currently running.\n\n"
                    L"Please close the game before installing Glitch.",
                    L"Glitch - Game Running", MB_OK | MB_ICONWARNING);
        return false;
    }
    if (!IsValidGameDir(g_app.game_dir)) {
        MessageBoxW(g_app.hwnd, L"Please select a valid Ratchet & Clank: Rift Apart folder containing RiftApart.exe.",
                    L"Glitch", MB_OK | MB_ICONWARNING);
        return false;
    }
    ExeVersion ver = ReadExeFileVersion(g_app.game_dir / "RiftApart.exe");
    if (!ver.MatchesExpected()) {
        std::wstring warn = L"Detected RiftApart.exe v" + ver.ToString() +
                            L", but Glitch was built for Steam v3.630.1.0.\n\n"
                            L"Patches whose target bytes do not match will be safely skipped at runtime.\n\n"
                            L"Install anyway?";
        if (MessageBoxW(g_app.hwnd, warn.c_str(), L"Glitch - Version Mismatch",
                        MB_YESNO | MB_ICONWARNING) != IDYES) {
            return false;
        }
    }
    if (!HasInstallPayloadIn(g_app.exe_dir)) {
        MessageBoxW(g_app.hwnd, L"Missing winmm.dll, Glitch.dll, or glitch\\patches next to GlitchConfig.exe.",
                    L"Glitch", MB_OK | MB_ICONERROR);
        return false;
    }

    std::error_code ec;
    auto copy_file_checked = [&](const fs::path& src, const fs::path& dst) -> bool {
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
        return !ec;
    };

    if (!copy_file_checked(g_app.exe_dir / "winmm.dll", g_app.game_dir / "winmm.dll") ||
        !copy_file_checked(g_app.exe_dir / "Glitch.dll", g_app.game_dir / "Glitch.dll") ||
        !copy_file_checked(g_app.exe_dir / "GlitchConfig.exe", g_app.game_dir / "GlitchConfig.exe")) {
        HandleFsError(ec, L"install Glitch files");
        return false;
    }

    fs::path dst_patches = g_app.game_dir / "glitch" / "patches";
    fs::path dst_ext = g_app.game_dir / "glitch" / "extensions";
    fs::create_directories(dst_patches, ec);
    fs::create_directories(dst_ext, ec);
    if (ec) {
        HandleFsError(ec, L"create glitch folders");
        return false;
    }

    for (const auto& entry : fs::directory_iterator(g_app.exe_dir / "glitch" / "patches", ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ".rvt") {
            if (!copy_file_checked(entry.path(), dst_patches / entry.path().filename())) {
                HandleFsError(ec, L"copy patch files");
                return false;
            }
        }
    }

    // Save current checkbox selections directly into the installed game_dir config.rvt.
    g_app.active_dir = g_app.game_dir;
    g_app.config_path = g_app.game_dir / "glitch" / "config.rvt";
    if (!SaveConfigTo(g_app.config_path)) {
        return false;
    }

    UpdateInstallButtons();
    SetStatusText(L"Installed Glitch to game folder!");
    return true;
}

void UninstallFromGameDir() {
    namespace fs = std::filesystem;
    if (!IsGlitchInstalledIn(g_app.game_dir)) return;
    if (IsProcessRunning(L"RiftApart.exe")) {
        MessageBoxW(g_app.hwnd,
                    L"Ratchet & Clank: Rift Apart (RiftApart.exe) is currently running.\n\n"
                    L"Please close the game before uninstalling Glitch.",
                    L"Glitch - Game Running", MB_OK | MB_ICONWARNING);
        return;
    }

    int res = MessageBoxW(
        g_app.hwnd,
        L"Remove Glitch (winmm.dll, Glitch.dll, and glitch\\ folder) from the game directory?\n\n"
        L"Your RiftApart.exe is completely untouched.",
        L"Uninstall Glitch", MB_YESNO | MB_ICONQUESTION);
    if (res != IDYES) return;

    std::error_code ec;
    fs::remove(g_app.game_dir / "winmm.dll", ec);
    if (ec) { HandleFsError(ec, L"remove winmm.dll"); return; }
    fs::remove(g_app.game_dir / "Glitch.dll", ec);
    if (ec) { HandleFsError(ec, L"remove Glitch.dll"); return; }
    fs::remove_all(g_app.game_dir / "glitch", ec);
    if (ec) { HandleFsError(ec, L"remove glitch folder"); return; }

    if (!PathsEqual(g_app.exe_dir, g_app.game_dir)) {
        fs::remove(g_app.game_dir / "GlitchConfig.exe", ec);
    }

    UpdateInstallButtons();
    SetStatusText(L"Glitch uninstalled cleanly.");
}

void LaunchGame() {
    std::filesystem::path exe = g_app.game_dir / "RiftApart.exe";
    if (IsValidGameDir(g_app.game_dir)) {
        HINSTANCE r = ShellExecuteW(
            g_app.hwnd, L"open", exe.c_str(), nullptr, g_app.game_dir.c_str(), SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(r) > 32) {
            PostQuitMessage(0);
            return;
        }
    }
    MessageBoxW(g_app.hwnd,
                L"Could not find RiftApart.exe.\n\n"
                L"Your settings were saved. Launch the game from Steam.",
                L"Glitch", MB_OK | MB_ICONINFORMATION);
}

void LayoutControls(int width, int height) {
    const int pad = 12;
    const int row_h = 26;
    const int header_h = 20;
    const int detail_h = 64;
    const int chk_h = 22;
    const int btn_h = 28;
    const int gap = 8;

    int y = pad;

    // Top Game Folder / Install bar
    const int lbl_w = 82;
    const int browse_w = 72;
    const int inst_w = 78;
    const int uninst_w = 78;
    int rx_top = width - pad - uninst_w;
    MoveWindow(g_app.hBtnUninst, rx_top, y, uninst_w, row_h, TRUE);
    rx_top -= (inst_w + 6);
    MoveWindow(g_app.hBtnInstall, rx_top, y, inst_w, row_h, TRUE);
    rx_top -= (browse_w + 6);
    MoveWindow(g_app.hBtnBrowse, rx_top, y, browse_w, row_h, TRUE);

    MoveWindow(g_app.hLblGame, pad, y + 5, lbl_w, 20, TRUE);
    int edit_x = pad + lbl_w + 4;
    int edit_w = std::max(100, rx_top - edit_x - 6);
    MoveWindow(g_app.hEditGame, edit_x, y + 1, edit_w, row_h - 2, TRUE);
    y += row_h + gap;

    MoveWindow(g_app.hHeader, pad, y, width - pad * 2, header_h, TRUE);
    y += header_h + gap;

    int bottom_block = detail_h + gap + chk_h + gap + btn_h + pad;
    int list_h = std::max(120, height - y - bottom_block - gap);
    MoveWindow(g_app.hList, pad, y, width - pad * 2, list_h, TRUE);
    y += list_h + gap;

    MoveWindow(g_app.hDetail, pad, y, width - pad * 2, detail_h, TRUE);
    y += detail_h + gap;

    MoveWindow(g_app.hChkConsole, pad, y, 300, chk_h, TRUE);
    y += chk_h + gap;

    int bx = pad;
    MoveWindow(g_app.hBtnAll, bx, y, 90, btn_h, TRUE);
    bx += 90 + 6;
    MoveWindow(g_app.hBtnNone, bx, y, 90, btn_h, TRUE);
    bx += 90 + 12;

    const int launch_w = 140;
    const int save_w = 84;
    int rx = width - pad - launch_w;
    MoveWindow(g_app.hBtnLaunch, rx, y, launch_w, btn_h, TRUE);
    rx -= (save_w + 6);
    MoveWindow(g_app.hBtnSave, rx, y, save_w, btn_h, TRUE);

    int status_w = std::max(40, rx - bx - 8);
    MoveWindow(g_app.hStatus, bx, y + 6, status_w, 20, TRUE);

    RECT rc_list = {};
    GetClientRect(g_app.hList, &rc_list);
    int col_sum = ListView_GetColumnWidth(g_app.hList, 0) +
                  ListView_GetColumnWidth(g_app.hList, 1);
    int rem = std::max(180, static_cast<int>(rc_list.right) - col_sum - 4);
    ListView_SetColumnWidth(g_app.hList, 2, rem);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_app.hwnd = hwnd;
            ApplyDarkTitleBar(hwnd);
            g_app.hBrushBg = CreateSolidBrush(CLR_BG);
            g_app.hBrushSurface = CreateSolidBrush(CLR_SURFACE);

            NONCLIENTMETRICSW ncm = {};
            ncm.cbSize = sizeof(ncm);
            if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
                g_app.hFont = CreateFontIndirectW(&ncm.lfMessageFont);
            } else {
                g_app.hFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            }

            HINSTANCE hInst = GetModuleHandleW(nullptr);
            auto set_font = [](HWND h) {
                SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g_app.hFont), TRUE);
            };

            g_app.hLblGame = CreateWindowExW(
                0, L"STATIC", L"Game Folder:",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                0, 0, 82, 20, hwnd, reinterpret_cast<HMENU>(IDC_LBL_GAME), hInst, nullptr);
            set_font(g_app.hLblGame);

            g_app.hEditGame = CreateWindowExW(
                0, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_AUTOHSCROLL,
                0, 0, 300, 24, hwnd, reinterpret_cast<HMENU>(IDC_EDIT_GAME), hInst, nullptr);
            set_font(g_app.hEditGame);
            SetWindowTheme(g_app.hEditGame, L"DarkMode_Explorer", nullptr);

            g_app.hBtnBrowse = CreateWindowExW(
                0, L"BUTTON", L"Browse...",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 72, 26, hwnd, reinterpret_cast<HMENU>(IDC_BTN_BROWSE), hInst, nullptr);
            set_font(g_app.hBtnBrowse);
            SetWindowTheme(g_app.hBtnBrowse, L"DarkMode_Explorer", nullptr);

            g_app.hBtnInstall = CreateWindowExW(
                0, L"BUTTON", L"Install",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 78, 26, hwnd, reinterpret_cast<HMENU>(IDC_BTN_INSTALL), hInst, nullptr);
            set_font(g_app.hBtnInstall);
            SetWindowTheme(g_app.hBtnInstall, L"DarkMode_Explorer", nullptr);

            g_app.hBtnUninst = CreateWindowExW(
                0, L"BUTTON", L"Uninstall",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 78, 26, hwnd, reinterpret_cast<HMENU>(IDC_BTN_UNINST), hInst, nullptr);
            set_font(g_app.hBtnUninst);
            SetWindowTheme(g_app.hBtnUninst, L"DarkMode_Explorer", nullptr);

            g_app.hHeader = CreateWindowExW(
                0, L"STATIC",
                L"Check or uncheck patches below, then click Save. Dependencies are managed automatically.",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                0, 0, 100, 20, hwnd, reinterpret_cast<HMENU>(IDC_HEADER), hInst, nullptr);
            set_font(g_app.hHeader);

            g_app.hList = CreateWindowExW(
                0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                0, 0, 100, 100, hwnd, reinterpret_cast<HMENU>(IDC_LIST), hInst, nullptr);
            set_font(g_app.hList);
            ListView_SetExtendedListViewStyle(
                g_app.hList,
                LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            SetWindowTheme(g_app.hList, L"DarkMode_Explorer", nullptr);
            ListView_SetBkColor(g_app.hList, CLR_SURFACE);
            ListView_SetTextBkColor(g_app.hList, CLR_SURFACE);
            ListView_SetTextColor(g_app.hList, CLR_TEXT);
            g_app.hListHeader = ListView_GetHeader(g_app.hList);
            if (g_app.hListHeader) {
                SetWindowTheme(g_app.hListHeader, L"DarkMode_ItemsView", nullptr);
                SetWindowSubclass(g_app.hList, ListViewDarkHeaderProc, 1, 0);
            }

            auto add_col = [](int idx, const wchar_t* title, int w) {
                LVCOLUMNW col = {};
                col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
                col.pszText = const_cast<wchar_t*>(title);
                col.cx = w;
                col.iSubItem = idx;
                ListView_InsertColumn(g_app.hList, idx, &col);
            };
            add_col(0, L"Patch", 225);
            add_col(1, L"Requires", 190);
            add_col(2, L"Description", 350);

            g_app.hDetail = CreateWindowExW(
                0, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                0, 0, 100, 60, hwnd, reinterpret_cast<HMENU>(IDC_DETAIL), hInst, nullptr);
            set_font(g_app.hDetail);
            SetWindowTheme(g_app.hDetail, L"DarkMode_Explorer", nullptr);

            g_app.hChkConsole = CreateWindowExW(
                0, L"BUTTON", L"Show debug console window on game launch",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                0, 0, 260, 22, hwnd, reinterpret_cast<HMENU>(IDC_CHK_CONSOLE), hInst, nullptr);
            set_font(g_app.hChkConsole);
            SetWindowTheme(g_app.hChkConsole, L"", L"");

            g_app.hBtnAll = CreateWindowExW(
                0, L"BUTTON", L"Enable All",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 90, 28, hwnd, reinterpret_cast<HMENU>(IDC_BTN_ALL), hInst, nullptr);
            set_font(g_app.hBtnAll);
            SetWindowTheme(g_app.hBtnAll, L"DarkMode_Explorer", nullptr);

            g_app.hBtnNone = CreateWindowExW(
                0, L"BUTTON", L"Disable All",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 90, 28, hwnd, reinterpret_cast<HMENU>(IDC_BTN_NONE), hInst, nullptr);
            set_font(g_app.hBtnNone);
            SetWindowTheme(g_app.hBtnNone, L"DarkMode_Explorer", nullptr);

            g_app.hStatus = CreateWindowExW(
                0, L"STATIC", L"",
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
                0, 0, 100, 20, hwnd, reinterpret_cast<HMENU>(IDC_STATUS), hInst, nullptr);
            set_font(g_app.hStatus);

            g_app.hBtnSave = CreateWindowExW(
                0, L"BUTTON", L"Save",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 84, 28, hwnd, reinterpret_cast<HMENU>(IDC_BTN_SAVE), hInst, nullptr);
            set_font(g_app.hBtnSave);
            SetWindowTheme(g_app.hBtnSave, L"DarkMode_Explorer", nullptr);

            g_app.hBtnLaunch = CreateWindowExW(
                0, L"BUTTON", L"Save && Launch Game",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                0, 0, 140, 28, hwnd, reinterpret_cast<HMENU>(IDC_BTN_LAUNCH), hInst, nullptr);
            set_font(g_app.hBtnLaunch);
            SetWindowTheme(g_app.hBtnLaunch, L"DarkMode_Explorer", nullptr);

            wchar_t exe_buf[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, exe_buf, MAX_PATH);
            g_app.exe_dir = std::filesystem::path(exe_buf).parent_path();
            g_app.game_dir = DetectGameDir(g_app.exe_dir);

            LoadPatchListFromActiveDir();
            PopulateListView();
            return 0;
        }

        case WM_ERASEBKGND: {
            HDC hdc = reinterpret_cast<HDC>(wParam);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, g_app.hBrushBg);
            return 1;
        }

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            HDC hdc = reinterpret_cast<HDC>(wParam);
            HWND hCtrl = reinterpret_cast<HWND>(lParam);
            if (hCtrl == g_app.hDetail || hCtrl == g_app.hEditGame) {
                SetTextColor(hdc, CLR_TEXT);
                SetBkColor(hdc, CLR_SURFACE);
                return reinterpret_cast<LRESULT>(g_app.hBrushSurface);
            }
            SetTextColor(hdc, (hCtrl == g_app.hHeader || hCtrl == g_app.hStatus) ? CLR_MUTED : CLR_TEXT);
            SetBkColor(hdc, CLR_BG);
            return reinterpret_cast<LRESULT>(g_app.hBrushBg);
        }

        case WM_CTLCOLOREDIT: {
            HDC hdc = reinterpret_cast<HDC>(wParam);
            SetTextColor(hdc, CLR_TEXT);
            SetBkColor(hdc, CLR_SURFACE);
            return reinterpret_cast<LRESULT>(g_app.hBrushSurface);
        }

        case WM_SIZE:
            LayoutControls(LOWORD(lParam), HIWORD(lParam));
            return 0;

        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            mmi->ptMinTrackSize.x = 660;
            mmi->ptMinTrackSize.y = 460;
            return 0;
        }

        case WM_NOTIFY: {
            auto* hdr = reinterpret_cast<NMHDR*>(lParam);
            if (hdr->idFrom == IDC_LIST && hdr->code == LVN_ITEMCHANGED) {
                auto* lv = reinterpret_cast<NMLISTVIEW*>(lParam);
                if (!g_app.updating && (lv->uChanged & LVIF_STATE)) {
                    UINT old_chk = (lv->uOldState & LVIS_STATEIMAGEMASK) >> 12;
                    UINT new_chk = (lv->uNewState & LVIS_STATEIMAGEMASK) >> 12;
                    if (old_chk != 0 && new_chk != 0 && old_chk != new_chk) {
                        OnItemToggled(static_cast<size_t>(lv->iItem), new_chk == 2);
                    }
                }
                if ((lv->uChanged & LVIF_STATE) && (lv->uNewState & LVIS_SELECTED)) {
                    UpdateDetailForSelection();
                }
            }
            return 0;
        }

        case WM_COMMAND: {
            const int id = LOWORD(wParam);
            if (id == IDC_BTN_BROWSE) {
                std::filesystem::path picked;
                if (BrowseForGameDir(hwnd, picked)) {
                    if (!IsValidGameDir(picked)) {
                        MessageBoxW(hwnd, L"RiftApart.exe was not found in the selected folder.",
                                    L"Glitch", MB_OK | MB_ICONWARNING);
                    } else {
                        g_app.game_dir = picked;
                        LoadPatchListFromActiveDir();
                        PopulateListView();
                    }
                }
            } else if (id == IDC_BTN_INSTALL) {
                InstallToGameDir();
            } else if (id == IDC_BTN_UNINST) {
                UninstallFromGameDir();
            } else if (id == IDC_CHK_CONSOLE) {
                g_app.dirty = true;
                UpdateCountStatus();
            } else if (id == IDC_BTN_ALL) {
                for (auto& it : g_app.items) it.checked = it.manifest_enabled;
                g_app.dirty = true;
                SyncListViewCheckmarks();
                UpdateCountStatus();
            } else if (id == IDC_BTN_NONE) {
                for (auto& it : g_app.items) it.checked = false;
                g_app.dirty = true;
                SyncListViewCheckmarks();
                UpdateCountStatus();
            } else if (id == IDC_BTN_SAVE) {
                if (IsValidGameDir(g_app.game_dir) && !IsGlitchInstalledIn(g_app.game_dir)) {
                    InstallToGameDir();
                } else {
                    SaveConfigTo(g_app.config_path);
                }
            } else if (id == IDC_BTN_LAUNCH) {
                bool ok = true;
                if (IsValidGameDir(g_app.game_dir) && !IsGlitchInstalledIn(g_app.game_dir)) {
                    ok = InstallToGameDir();
                } else {
                    ok = SaveConfigTo(g_app.config_path);
                }
                if (ok) {
                    LaunchGame();
                }
            }
            return 0;
        }

        case WM_DESTROY:
            if (g_app.hFont) DeleteObject(g_app.hFont);
            if (g_app.hBrushBg) DeleteObject(g_app.hBrushBg);
            if (g_app.hBrushSurface) DeleteObject(g_app.hBrushSurface);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    SetProcessDPIAware();
    EnableDarkModeApp();
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(CLR_BG);
    wc.lpszClassName = L"GlitchConfigWnd";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        0, wc.lpszClassName, L"Glitch - Patch Manager",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 820, 580,
        nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) {
        CoUninitialize();
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    CoUninitialize();
    return static_cast<int>(msg.wParam);
}
