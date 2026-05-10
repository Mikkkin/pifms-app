#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>

#include "common/constants.h"
#include "gui/rpc_client.h"
#include "gui/service_guard.h"

#include <string_view>
#include <string>

namespace {

constexpr UINT kTrayIconMessage = WM_USER + 1;

namespace CommandId {
constexpr UINT kTrayOpen = 1001;
constexpr UINT kTrayExit = 1002;
constexpr UINT kFileExit = 2001;
constexpr UINT kLogin = 3001;
constexpr UINT kLogout = 3002;
constexpr UINT kActivate = 3003;
constexpr UINT kScan = 3004;
} 

namespace Text {
constexpr wchar_t kMutexName[] = L"PIFMSApp_SingleInstance";
constexpr wchar_t kWindowClass[] = L"PIFMSAppMainWindow";
constexpr wchar_t kWindowTitle[] = L"PIFMS Application";
constexpr wchar_t kFileMenu[] = L"Файл";
constexpr wchar_t kOpen[] = L"Открыть";
constexpr wchar_t kExit[] = L"Выход";
constexpr wchar_t kLoginTitle[] = L"Вход в учётную запись";
constexpr wchar_t kUsername[] = L"Логин";
constexpr wchar_t kPassword[] = L"Пароль";
constexpr wchar_t kLogin[] = L"Войти";
constexpr wchar_t kLogout[] = L"Выйти";
constexpr wchar_t kActivationTitle[] = L"Активация продукта";
constexpr wchar_t kActivationCode[] = L"Код активации";
constexpr wchar_t kActivate[] = L"Активировать";
constexpr wchar_t kUserPrefix[] = L"Пользователь: ";
constexpr wchar_t kNoUser[] = L"Пользователь: не выполнен вход";
constexpr wchar_t kLicensePrefix[] = L"Лицензия действительна до: ";
constexpr wchar_t kNoLicense[] = L"Лицензия отсутствует";
constexpr wchar_t kAntivirusLocked[] = L"Функциональность антивируса заблокирована";
constexpr wchar_t kAntivirusReady[] = L"Функциональность антивируса доступна";
constexpr wchar_t kScan[] = L"Проверить систему";
} 

[[nodiscard]] bool IsServiceChildMode(std::wstring_view commandLine)
{
    return commandLine.find(pifms::kServiceChildArg) != std::wstring_view::npos;
}

struct AppState {
    HINSTANCE instance = nullptr;
    HWND window = nullptr;
    NOTIFYICONDATAW trayIcon = {};
    UINT taskbarCreatedMessage = 0;
    pifms::gui::UserInfo user;
    pifms::gui::LicenseInfo license;
    bool hasLicense = false;
    HWND userLabel = nullptr;
    HWND licenseLabel = nullptr;
    HWND antivirusStatusLabel = nullptr;
    HWND scanButton = nullptr;
    HWND loginTitleLabel = nullptr;
    HWND usernameLabel = nullptr;
    HWND usernameEdit = nullptr;
    HWND passwordLabel = nullptr;
    HWND passwordEdit = nullptr;
    HWND loginButton = nullptr;
    HWND logoutButton = nullptr;
    HWND activationTitleLabel = nullptr;
    HWND activationCodeLabel = nullptr;
    HWND activationCodeEdit = nullptr;
    HWND activateButton = nullptr;
    HWND errorLabel = nullptr;
};

class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE handle) noexcept
        : handle_(handle)
    {
    }

    ~UniqueHandle()
    {
        if (IsValid()) {
            CloseHandle(handle_);
        }
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return IsValid();
    }

private:
    [[nodiscard]] bool IsValid() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE handle_ = nullptr;
};

AppState g_app;

[[nodiscard]] bool AddTrayIcon(HWND hwnd)
{
    g_app.trayIcon = {};
    g_app.trayIcon.cbSize = sizeof(g_app.trayIcon);
    g_app.trayIcon.hWnd = hwnd;
    g_app.trayIcon.uID = 1;
    g_app.trayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_app.trayIcon.uCallbackMessage = kTrayIconMessage;
    g_app.trayIcon.hIcon = LoadIconW(nullptr, IDI_APPLICATION);

    const HRESULT copyResult = StringCchCopyW(
        g_app.trayIcon.szTip,
        ARRAYSIZE(g_app.trayIcon.szTip),
        Text::kWindowTitle
    );

    if (FAILED(copyResult)) {
        return false;
    }

    return Shell_NotifyIconW(NIM_ADD, &g_app.trayIcon) == TRUE;
}

void RemoveTrayIcon()
{
    Shell_NotifyIconW(NIM_DELETE, &g_app.trayIcon);
    g_app.trayIcon = {};
}

void ShowMainWindow()
{
    ShowWindow(g_app.window, SW_SHOW);
    SetForegroundWindow(g_app.window);
}

[[nodiscard]] std::wstring GetWindowTextValue(HWND window)
{
    const int length = GetWindowTextLengthW(window);
    if (length <= 0) {
        return {};
    }

    std::wstring value(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(window, value.data(), length + 1);
    value.resize(static_cast<size_t>(length));
    return value;
}

void SetControlText(HWND control, const std::wstring& text)
{
    SetWindowTextW(control, text.c_str());
}

void SetControlVisible(HWND control, bool visible)
{
    ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
}

void SetErrorMessage(const std::wstring& message)
{
    SetControlText(g_app.errorLabel, message);
}

[[nodiscard]] HWND CreateStatic(HWND parent, const wchar_t* text, int x, int y, int width, int height)
{
    return CreateWindowW(
        L"STATIC",
        text,
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        x,
        y,
        width,
        height,
        parent,
        nullptr,
        g_app.instance,
        nullptr
    );
}

[[nodiscard]] HWND CreateEdit(HWND parent, int x, int y, int width, int height, bool password)
{
    return CreateWindowW(
        L"EDIT",
        L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | (password ? ES_PASSWORD : 0),
        x,
        y,
        width,
        height,
        parent,
        nullptr,
        g_app.instance,
        nullptr
    );
}

[[nodiscard]] HWND CreateButton(HWND parent, const wchar_t* text, UINT commandId, int x, int y, int width, int height)
{
    return CreateWindowW(
        L"BUTTON",
        text,
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        x,
        y,
        width,
        height,
        parent,
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(commandId)),
        g_app.instance,
        nullptr
    );
}

void RenderScreen()
{
    const bool authenticated = g_app.user.authenticated;
    const bool licenseActive = authenticated && g_app.hasLicense && g_app.license.active;
    const bool showLoginForm = !authenticated;
    const bool showActivationForm = authenticated && !licenseActive;

    SetControlText(
        g_app.userLabel,
        authenticated ? std::wstring(Text::kUserPrefix) + g_app.user.username : Text::kNoUser
    );

    if (licenseActive) {
        SetControlText(g_app.licenseLabel, std::wstring(Text::kLicensePrefix) + g_app.license.expirationDate);
    } else {
        SetControlText(g_app.licenseLabel, Text::kNoLicense);
    }

    SetControlText(
        g_app.antivirusStatusLabel,
        licenseActive ? Text::kAntivirusReady : Text::kAntivirusLocked
    );
    EnableWindow(g_app.scanButton, licenseActive ? TRUE : FALSE);

    SetControlVisible(g_app.loginTitleLabel, showLoginForm);
    SetControlVisible(g_app.usernameLabel, showLoginForm);
    SetControlVisible(g_app.usernameEdit, showLoginForm);
    SetControlVisible(g_app.passwordLabel, showLoginForm);
    SetControlVisible(g_app.passwordEdit, showLoginForm);
    SetControlVisible(g_app.loginButton, showLoginForm);
    SetControlVisible(g_app.logoutButton, authenticated);

    SetControlVisible(g_app.activationTitleLabel, showActivationForm);
    SetControlVisible(g_app.activationCodeLabel, showActivationForm);
    SetControlVisible(g_app.activationCodeEdit, showActivationForm);
    SetControlVisible(g_app.activateButton, showActivationForm);

    if (showLoginForm || showActivationForm) {
        ShowMainWindow();
    }
}

void RefreshLicenseState(bool showErrors)
{
    if (!g_app.user.authenticated) {
        g_app.hasLicense = false;
        g_app.license = {};
        RenderScreen();
        return;
    }

    pifms::gui::LicenseInfo license;
    const long result = pifms::gui::GetLicenseInfo(license);
    g_app.license = license;
    g_app.hasLicense = result == pifms::rpc_result::kOk && license.active;

    if (result == pifms::rpc_result::kNoLicense) {
        g_app.hasLicense = false;
        if (showErrors) {
            SetErrorMessage(pifms::gui::RpcResultMessage(result));
        }
    } else if (result != pifms::rpc_result::kOk && showErrors) {
        SetErrorMessage(pifms::gui::RpcResultMessage(result));
    } else if (result == pifms::rpc_result::kOk) {
        SetErrorMessage(L"");
    }

    RenderScreen();
}

void RefreshUserState()
{
    pifms::gui::UserInfo user;
    const long result = pifms::gui::GetCurrentUser(user);
    if (result != pifms::rpc_result::kOk) {
        g_app.user = {};
        g_app.hasLicense = false;
        SetErrorMessage(pifms::gui::RpcResultMessage(result));
        RenderScreen();
        return;
    }

    g_app.user = user;
    SetErrorMessage(L"");
    RenderScreen();

    if (g_app.user.authenticated) {
        RefreshLicenseState(false);
    }
}

void HandleLogin()
{
    const std::wstring username = GetWindowTextValue(g_app.usernameEdit);
    std::wstring password = GetWindowTextValue(g_app.passwordEdit);
    if (username.empty() || password.empty()) {
        SetErrorMessage(L"Введите логин и пароль");
        RenderScreen();
        return;
    }

    pifms::gui::UserInfo user;
    const long result = pifms::gui::Login(username, password, user);
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    SetWindowTextW(g_app.passwordEdit, L"");

    if (result != pifms::rpc_result::kOk) {
        g_app.user = {};
        g_app.hasLicense = false;
        SetErrorMessage(pifms::gui::RpcResultMessage(result));
        RenderScreen();
        return;
    }

    g_app.user = user;
    SetErrorMessage(L"");
    RenderScreen();
    RefreshLicenseState(true);
}

void HandleLogout()
{
    static_cast<void>(pifms::gui::Logout());
    g_app.user = {};
    g_app.license = {};
    g_app.hasLicense = false;
    SetErrorMessage(L"");
    RenderScreen();
}

void HandleActivation()
{
    const std::wstring activationCode = GetWindowTextValue(g_app.activationCodeEdit);
    if (activationCode.empty()) {
        SetErrorMessage(L"Введите код активации");
        RenderScreen();
        return;
    }

    pifms::gui::LicenseInfo license;
    const long result = pifms::gui::ActivateProduct(activationCode, license);
    if (result != pifms::rpc_result::kOk || !license.active) {
        g_app.license = license;
        g_app.hasLicense = false;
        SetErrorMessage(pifms::gui::RpcResultMessage(result));
        RenderScreen();
        return;
    }

    g_app.license = license;
    g_app.hasLicense = true;
    SetWindowTextW(g_app.activationCodeEdit, L"");
    SetErrorMessage(L"");
    RenderScreen();
}

void ExitApplication()
{
    RemoveTrayIcon();
    PostQuitMessage(0);
}

[[nodiscard]] HMENU CreateTrayMenu()
{
    HMENU menu = CreatePopupMenu();
    if (!menu) {
        return nullptr;
    }

    if (!AppendMenuW(menu, MF_STRING, CommandId::kTrayOpen, Text::kOpen) ||
        !AppendMenuW(menu, MF_STRING, CommandId::kTrayExit, Text::kExit)) {
        DestroyMenu(menu);
        return nullptr;
    }

    return menu;
}

void ShowTrayContextMenu()
{
    HMENU menu = CreateTrayMenu();
    if (!menu) {
        return;
    }

    POINT cursorPosition = {};
    if (!GetCursorPos(&cursorPosition)) {
        DestroyMenu(menu);
        return;
    }

    SetForegroundWindow(g_app.window);

    TrackPopupMenu(
        menu,
        TPM_BOTTOMALIGN | TPM_RIGHTALIGN,
        cursorPosition.x,
        cursorPosition.y,
        0,
        g_app.window,
        nullptr
    );

    DestroyMenu(menu);
}

[[nodiscard]] HMENU CreateMainMenuBar()
{
    HMENU menuBar = CreateMenu();
    if (!menuBar) {
        return nullptr;
    }

    HMENU fileMenu = CreatePopupMenu();
    if (!fileMenu) {
        DestroyMenu(menuBar);
        return nullptr;
    }

    if (!AppendMenuW(fileMenu, MF_STRING, CommandId::kFileExit, Text::kExit)) {
        DestroyMenu(fileMenu);
        DestroyMenu(menuBar);
        return nullptr;
    }

    if (!AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), Text::kFileMenu)) {
        DestroyMenu(fileMenu);
        DestroyMenu(menuBar);
        return nullptr;
    }

    return menuBar;
}

[[nodiscard]] bool CreateMainWindowContent(HWND hwnd)
{
    g_app.userLabel = CreateStatic(hwnd, Text::kNoUser, 20, 20, 520, 24);
    g_app.logoutButton = CreateButton(hwnd, Text::kLogout, CommandId::kLogout, 640, 18, 120, 28);
    g_app.licenseLabel = CreateStatic(hwnd, Text::kNoLicense, 20, 52, 740, 24);
    g_app.antivirusStatusLabel = CreateStatic(hwnd, Text::kAntivirusLocked, 20, 92, 420, 24);
    g_app.scanButton = CreateButton(hwnd, Text::kScan, CommandId::kScan, 20, 124, 240, 34);

    g_app.loginTitleLabel = CreateStatic(hwnd, Text::kLoginTitle, 20, 180, 240, 24);
    g_app.usernameLabel = CreateStatic(hwnd, Text::kUsername, 20, 216, 120, 24);
    g_app.usernameEdit = CreateEdit(hwnd, 150, 212, 260, 28, false);
    g_app.passwordLabel = CreateStatic(hwnd, Text::kPassword, 20, 252, 120, 24);
    g_app.passwordEdit = CreateEdit(hwnd, 150, 248, 260, 28, true);
    g_app.loginButton = CreateButton(hwnd, Text::kLogin, CommandId::kLogin, 150, 292, 120, 32);

    g_app.activationTitleLabel = CreateStatic(hwnd, Text::kActivationTitle, 20, 180, 260, 24);
    g_app.activationCodeLabel = CreateStatic(hwnd, Text::kActivationCode, 20, 216, 120, 24);
    g_app.activationCodeEdit = CreateEdit(hwnd, 150, 212, 320, 28, false);
    g_app.activateButton = CreateButton(hwnd, Text::kActivate, CommandId::kActivate, 150, 252, 140, 32);

    g_app.errorLabel = CreateStatic(hwnd, L"", 20, 340, 740, 48);

    return g_app.userLabel != nullptr &&
           g_app.logoutButton != nullptr &&
           g_app.licenseLabel != nullptr &&
           g_app.antivirusStatusLabel != nullptr &&
           g_app.scanButton != nullptr &&
           g_app.loginTitleLabel != nullptr &&
           g_app.usernameLabel != nullptr &&
           g_app.usernameEdit != nullptr &&
           g_app.passwordLabel != nullptr &&
           g_app.passwordEdit != nullptr &&
           g_app.loginButton != nullptr &&
           g_app.activationTitleLabel != nullptr &&
           g_app.activationCodeLabel != nullptr &&
           g_app.activationCodeEdit != nullptr &&
           g_app.activateButton != nullptr &&
           g_app.errorLabel != nullptr;
}

void HandleCommand(WPARAM wParam)
{
    switch (LOWORD(wParam)) {
    case CommandId::kTrayOpen:
        ShowMainWindow();
        break;

    case CommandId::kTrayExit:
    case CommandId::kFileExit:
        static_cast<void>(pifms::gui::RequestServiceStop());
        ExitApplication();
        break;

    case CommandId::kLogin:
        HandleLogin();
        break;

    case CommandId::kLogout:
        HandleLogout();
        break;

    case CommandId::kActivate:
        HandleActivation();
        break;

    case CommandId::kScan:
        if (pifms::gui::EnsureAntivirusAvailable() == pifms::rpc_result::kOk) {
            MessageBoxW(g_app.window, L"Проверка доступна при активной лицензии", Text::kWindowTitle, MB_OK);
        } else {
            SetErrorMessage(pifms::gui::RpcResultMessage(pifms::rpc_result::kNoLicense));
            RefreshLicenseState(false);
        }
        break;

    default:
        break;
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (g_app.taskbarCreatedMessage != 0 && message == g_app.taskbarCreatedMessage) {
        static_cast<void>(AddTrayIcon(hwnd));
        return 0;
    }

    switch (message) {
    case WM_CREATE:
        g_app.window = hwnd;
        if (!CreateMainWindowContent(hwnd)) {
            return -1;
        }
        SetTimer(hwnd, 1, 10000, nullptr);
        RefreshUserState();
        return 0;

    case kTrayIconMessage:
        if (lParam == WM_LBUTTONUP) {
            ShowMainWindow();
        } else if (lParam == WM_RBUTTONUP) {
            ShowTrayContextMenu();
        }
        return 0;

    case WM_COMMAND:
        HandleCommand(wParam);
        return 0;

    case WM_TIMER:
        RefreshLicenseState(false);
        return 0;

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, 1);
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}

[[nodiscard]] bool IsSilentMode(std::wstring_view commandLine)
{
    return commandLine.find(L"/silent") != std::wstring_view::npos ||
           commandLine.find(L"--silent") != std::wstring_view::npos;
}

[[nodiscard]] bool RegisterMainWindowClass()
{
    WNDCLASSEXW windowClass = {};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = g_app.instance;
    windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = Text::kWindowClass;

    return RegisterClassExW(&windowClass) != 0;
}

[[nodiscard]] bool CreateMainWindow()
{
    HMENU menuBar = CreateMainMenuBar();
    if (!menuBar) {
        return false;
    }

    g_app.window = CreateWindowExW(
        0,
        Text::kWindowClass,
        Text::kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        800,
        600,
        nullptr,
        menuBar,
        g_app.instance,
        nullptr
    );

    if (!g_app.window) {
        DestroyMenu(menuBar);
        return false;
    }

    return true;
}

int RunMessageLoop()
{
    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(message.wParam);
}

} 

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR commandLine, int)
{
    const std::wstring_view commandLineView = commandLine != nullptr ? commandLine : L"";

    if (pifms::gui::CheckServiceStartup() == pifms::gui::StartupDecision::Exit) {
        return 0;
    }

    if (!IsServiceChildMode(commandLineView) || !pifms::gui::IsParentServiceProcess()) {
        return 0;
    }

    UniqueHandle singleInstanceMutex(CreateMutexW(nullptr, TRUE, Text::kMutexName));
    if (!singleInstanceMutex) {
        return 1;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }

    g_app.instance = instance;
    g_app.taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    if (!RegisterMainWindowClass() || !CreateMainWindow()) {
        return 1;
    }

    if (!IsSilentMode(commandLineView)) {
        ShowWindow(g_app.window, SW_SHOW);
    }

    if (!AddTrayIcon(g_app.window)) {
        return 1;
    }

    return RunMessageLoop();
}
