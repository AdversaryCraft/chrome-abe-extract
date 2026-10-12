# chrome-abe-extract

A proof-of-concept demonstrating a path-validation bypass in Chrome's App-Bound Encryption (ABE) elevation service on Windows.

Extracts and decrypts cookies, passwords, credit cards, IBANs, and autofill data from a Chrome profile by recovering the ABE master key through Chrome's own COM interface.

**Full writeup:** [Bypassing Chrome's App-Bound Encryption With a File Copy](https://adversarycraft.com/2026/10/12/bypassing-chromes-app-bound-encryption-with-a-file-copy/)

**For authorized security research and lab use only.**

---

## Background

Chrome 127 introduced App-Bound Encryption to prevent infostealers from accessing browser data. The design wraps a profile-wide AES-256 master key in two layers of DPAPI encryption and gates decryption behind a SYSTEM-level elevation service. Before releasing the key, the service validates that the caller's executable resides in Chrome's install directory.

That validation is directory-based, not identity-based. Any process running from `C:\Program Files\Google\Chrome\Application\` satisfies it, regardless of filename or code signature.

This technique is documented in [CyberArk Labs' C4 research](https://web.archive.org/web/20251116044735/https://www.cyberark.com/resources/threat-research-blog/c4-bomb-blowing-up-chromes-appbound-cookie-encryption) (June 2025). The CVE originally assigned to it (CVE-2025-34092) was later rejected by the NVD. The rejection does not change the underlying technical finding — the technique remains functional against Chrome builds with ABE enabled.

---

## What It Does

1. Reads `app_bound_encrypted_key` from `Local State`
2. Base64-decodes the value and strips the `APPB` header
3. Calls `IElevator::DecryptData` via COM to recover the 32-byte master key
4. Decrypts v20 blobs with AES-256-GCM via BCrypt
5. Writes everything to `C:\testing\abe_dump.json`

---

## Supported Data

| Type | Database | Table |
|------|----------|-------|
| Cookies | `Default\Network\Cookies` | `cookies` |
| Passwords | `Default\Login Data` | `logins` |
| Credit cards | `Default\Web Data` | `credit_cards` |
| IBANs | `Default\Web Data` | `local_ibans` |
| Autofill | `Default\Web Data` | `autofill` |

---

## Build

**Prerequisites:** Visual Studio 2022 with the Desktop development with C++ workload, plus the SQLite amalgamation which is already available in this repo (`sqlite3.c` and `sqlite3.h`).
.

Open the **x64 Native Tools Command Prompt for VS 2022** and run:

```cmd
cl /nologo /EHsc /O2 /MT /W3 /D_UNICODE /DUNICODE ^
   /I third_party/sqlite3 ^
   src/chrome_abe_extract.cpp ^
   third_party/sqlite3/sqlite3.c ^
   /Fe:chrome_abe_extract.exe ^
   /link /SUBSYSTEM:CONSOLE ^
   ole32.lib oleaut32.lib bcrypt.lib shell32.lib advapi32.lib ^
   shlwapi.lib crypt32.lib rpcrt4.lib
```

Warnings from `sqlite3.c` are expected — the amalgamation is not warning-clean under MSVC.

---

## Usage

**Step 1 — Copy the executable into Chrome's install directory** (requires Administrator):

```cmd
copy chrome_abe_extract.exe "C:\Program Files\Google\Chrome\Application\"
```

**Step 2 — Close Chrome:**

```cmd
taskkill /F /IM chrome.exe /T
```

**Step 3 — Run from a NON-elevated command prompt:**

```cmd
"C:\Program Files\Google\Chrome\Application\chrome_abe_extract.exe"
```

Output: `C:\testing\abe_dump.json`

### Note on the elevation service

You do **not** need to manually start `GoogleChromeElevationService` before running the tool. When the tool calls `CoCreateInstance(CLSID_Elevator, ..., CLSCTX_LOCAL_SERVER, ...)`, the Windows Service Control Manager starts the service on demand if it isn't already running. This is standard behavior for COM objects hosted as local services — the registration in the registry tells the SCM how to launch the server, and `CoCreateInstance` triggers it.

The only case where this fails is if the service has been set to **Disabled** (not just Stopped). In that state the SCM refuses to launch it, and `CoCreateInstance` returns an error that propagates as `0x8004a003` at the `DecryptData` call. If you see that error, check the service state with `sc query "GoogleChromeElevationService"` — if it shows `DISABLED`, that's the cause.

---

## Common Errors

| HRESULT | Meaning | Fix |
|---------|---------|-----|
| `0x8004a004` | Path validation rejected | Run from Chrome's install directory |
| `0x8004a003` | Service unreachable, or wrong user context | Check service isn't Disabled; run as normal user (not elevated) |
| `ERROR_ACCESS_DENIED` | Running elevated | Use a non-elevated prompt |

---

## Testing

Verified against Chrome 153 on Windows 11 with **Microsoft Defender for Business** enabled (no exclusions).

| Stage | Result |
|-------|--------|
| Copy to Chrome's install dir | Allowed |
| First execution from Chrome's folder | Allowed |
| `CoCreateInstance(CLSID_Elevator)` | Not detected |
| Reads of `Local State` and DB files | Not detected |
| End-to-end run | Completed |
| Alert generated | None |

Defender for Business produced zero alerts at any stage.

**Caveat:** This result is specific to Defender for Business—the SMB SKU designed for companies up to 300 users. It says nothing about Defender for Endpoint Plan 2, which adds KQL-based advanced hunting, 6 months of data retention, and managed threat hunting through Microsoft Threat Experts. It also says nothing about Defender XDR, which correlates endpoint signals with identity, email, and cloud telemetry.

---

## Detection

Indicators defenders can look for:

- Non-`chrome.exe` binaries in `C:\Program Files\Google\Chrome\Application\`
- Any process outside Chrome instantiating the `IElevator` COM object
- Reads of `Local State`, `Login Data`, and `Web Data` from the same unexpected process
- Sysmon Event 1 for process creation in Chrome's install directory

None of these alone is damning. Together, they are a clean signature.

---

## Limitations

- Targets the `Default` profile only
- Requires Administrator to write to Chrome's install directory (one-time copy)
- Chrome must be closed before extracting from `Login Data` and `Web Data` (SQLite locks)

---

## Repository Structure

```
chrome-abe-extract/
├── README.md
├── LICENSE
├── .gitignore
├── src/
│   └── chrome_abe_extract.cpp
├── third_party/
│   └── sqlite3/
│       ├── sqlite3.c
│       └── sqlite3.h
```


---

## Ethics

This tool is published for defensive research, detection engineering, and security education.

The technique itself is public. The purpose of this repository is to document the bypass so that detection engineers can build rules against it, security teams can assess whether their EDR catches it, and users understand why the ABE control, as implemented, is insufficient.

Running this tool against systems you do not own is a criminal offense in most jurisdictions. The author does not condone, support, or assist with unauthorized use.
