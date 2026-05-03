#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>

#include "common/constants.h"
#include "gui/rpc_client.h"
#include "gui/service_guard.h"

#include <string_view>

namespace {

constexpr UINT kTrayIconMessage = WM_USER + 1;

namespace CommandId {
constexpr UINT kTrayOpen = 1001;
constexpr UINT kTrayExit = 1002;
constexpr UINT kFileExit = 2001;
} 

namespace Text {
constexpr wchar_t kMutexName[] = L"PIFMSApp_SingleInstance";
constexpr wchar_t kWindowClass[] = L"PIFMSAppMainWindow";
constexpr wchar_t kWindowTitle[] = L"PIFMS Application";
constexpr wchar_t kFileMenu[] = L"Файл";
constexpr wchar_t kOpen[] = L"Открыть";
constexpr wchar_t kExit[] = L"Выход";
constexpr wchar_t kRunningMessage[] = L"Test message just for fun";
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
    return CreateWindowW(
        L"STATIC",
        Text::kRunningMessage,
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        20,
        20,
        740,
        30,
        hwnd,
        nullptr,
        g_app.instance,
        nullptr
    ) != nullptr;
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
        return CreateMainWindowContent(hwnd) ? 0 : -1;

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

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
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
