#include "service/antivirus_service.h"

#include "common/constants.h"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string_view>

namespace {

constexpr std::size_t kMaxResults = pifms::kRpcScanResultCapacity;
constexpr std::int64_t kDatabaseUpdateIntervalSeconds = 5 * 60;
constexpr wchar_t kDatabaseDirectory[] = L"PIFMS\\avdb";
constexpr wchar_t kDatabaseFilename[] = L"signatures.pifmsdb";
constexpr wchar_t kBackupDatabaseFilename[] = L"signatures.pifmsdb.bak";
constexpr wchar_t kTemporaryDatabaseFilename[] = L"signatures.pifmsdb.tmp";
constexpr wchar_t kDefaultDatabaseRelativePath[] = L"resources\\avdb\\default.pifmsdb";
constexpr wchar_t kCertificateRelativePath[] = L"resources\\avdb\\signing.crt";

std::int64_t NowUnixSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

class CriticalSectionLock {
public:
    explicit CriticalSectionLock(CRITICAL_SECTION& section) noexcept
        : section_(section)
    {
        EnterCriticalSection(&section_);
    }

    ~CriticalSectionLock()
    {
        LeaveCriticalSection(&section_);
    }

    CriticalSectionLock(const CriticalSectionLock&) = delete;
    CriticalSectionLock& operator=(const CriticalSectionLock&) = delete;

private:
    CRITICAL_SECTION& section_;
};

class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept
        : handle_(handle)
    {
    }

    ~UniqueHandle()
    {
        Reset();
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    [[nodiscard]] HANDLE Get() const noexcept
    {
        return handle_;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    void Reset(HANDLE handle = nullptr) noexcept
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

void LimitResults(std::vector<pifms::service::ScanResult>& results)
{
    if (results.size() > kMaxResults) {
        results.resize(kMaxResults);
    }
}

void AppendFileScan(
    const pifms::service::AntivirusDatabase& database,
    const std::wstring& path,
    std::vector<pifms::service::ScanResult>& results
)
{
    if (results.size() >= kMaxResults) {
        return;
    }

    pifms::service::AntivirusEngine engine(database);
    results.push_back(engine.ScanFile(path));
}

void AppendDirectoryScan(
    const pifms::service::AntivirusDatabase& database,
    const std::wstring& path,
    std::vector<pifms::service::ScanResult>& results
)
{
    std::error_code error;
    if (!std::filesystem::exists(path, error)) {
        pifms::service::ScanResult result;
        result.path = path;
        result.error = L"Путь не найден";
        results.push_back(std::move(result));
        return;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             path,
             std::filesystem::directory_options::skip_permission_denied,
             error)) {
        if (results.size() >= kMaxResults) {
            break;
        }
        if (error) {
            error.clear();
            continue;
        }
        if (!entry.is_regular_file(error)) {
            error.clear();
            continue;
        }
        AppendFileScan(database, entry.path().wstring(), results);
    }
}

std::vector<std::wstring> FixedDriveRoots()
{
    DWORD required = GetLogicalDriveStringsW(0, nullptr);
    if (required == 0) {
        return {};
    }

    std::wstring buffer(required + 1, L'\0');
    DWORD written = GetLogicalDriveStringsW(required, buffer.data());
    if (written == 0 || written > required) {
        return {};
    }

    std::vector<std::wstring> drives;
    const wchar_t* current = buffer.c_str();
    while (*current != L'\0') {
        std::wstring drive = current;
        if (GetDriveTypeW(drive.c_str()) == DRIVE_FIXED) {
            drives.push_back(std::move(drive));
        }
        current += wcslen(current) + 1;
    }
    return drives;
}

std::wstring JoinPath(const std::wstring& directory, std::wstring_view filename)
{
    std::filesystem::path path(directory);
    path /= std::wstring(filename);
    return path.wstring();
}

std::wstring ExecutableDirectory()
{
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return {};
        }
        if (length < path.size() - 1) {
            path.resize(length);
            break;
        }
        path.resize(path.size() * 2);
    }

    const std::size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return {};
    }
    path.resize(separator);
    return path;
}

std::wstring ProgramDataDirectory()
{
    DWORD required = GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
    if (required == 0) {
        return L"C:\\ProgramData";
    }

    std::wstring value(required, L'\0');
    DWORD written = GetEnvironmentVariableW(L"ProgramData", value.data(), required);
    if (written == 0 || written >= required) {
        return L"C:\\ProgramData";
    }
    value.resize(written);
    return value;
}

std::wstring DatabaseDirectory()
{
    return JoinPath(ProgramDataDirectory(), kDatabaseDirectory);
}

std::wstring MainDatabasePath()
{
    return JoinPath(DatabaseDirectory(), kDatabaseFilename);
}

std::wstring BackupDatabasePath()
{
    return JoinPath(DatabaseDirectory(), kBackupDatabaseFilename);
}

std::wstring TemporaryDatabasePath()
{
    return JoinPath(DatabaseDirectory(), kTemporaryDatabaseFilename);
}

std::wstring DefaultDatabasePath()
{
    return JoinPath(ExecutableDirectory(), kDefaultDatabaseRelativePath);
}

std::wstring CertificatePath()
{
    return JoinPath(ExecutableDirectory(), kCertificateRelativePath);
}

bool ReadAllBytes(const std::wstring& path, std::vector<std::uint8_t>& data)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return !data.empty();
}

bool WriteAllBytes(const std::wstring& path, const std::vector<std::uint8_t>& data)
{
    std::error_code error;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), error);
    if (error) {
        return false;
    }

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return file.good();
}

bool ReplaceFileWith(const std::wstring& source, const std::wstring& destination)
{
    std::error_code error;
    std::filesystem::rename(source, destination, error);
    if (!error) {
        return true;
    }

    error.clear();
    std::filesystem::copy_file(source, destination, std::filesystem::copy_options::overwrite_existing, error);
    if (error) {
        return false;
    }

    error.clear();
    std::filesystem::remove(source, error);
    return true;
}

void CopyIfExists(const std::wstring& source, const std::wstring& destination)
{
    std::error_code error;
    if (!std::filesystem::exists(source, error)) {
        return;
    }
    error.clear();
    std::filesystem::create_directories(std::filesystem::path(destination).parent_path(), error);
    if (error) {
        return;
    }
    error.clear();
    std::filesystem::copy_file(source, destination, std::filesystem::copy_options::overwrite_existing, error);
}

}

namespace pifms::service {

AntivirusService::AntivirusService()
{
    InitializeCriticalSection(&lock_);
    scheduleStopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    monitorStopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    databaseUpdateStopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

AntivirusService::~AntivirusService()
{
    StopDatabaseUpdateThread();
    StopScheduleThread();
    StopMonitorThread();
    if (scheduleStopEvent_ != nullptr) {
        CloseHandle(scheduleStopEvent_);
    }
    if (monitorStopEvent_ != nullptr) {
        CloseHandle(monitorStopEvent_);
    }
    if (databaseUpdateStopEvent_ != nullptr) {
        CloseHandle(databaseUpdateStopEvent_);
    }
    DeleteCriticalSection(&lock_);
}

void AntivirusService::Start(SessionManager& sessionManager)
{
    StartDatabaseUpdateThread(sessionManager);

    bool shouldLoad = false;
    {
        CriticalSectionLock lock(lock_);
        shouldLoad = !localLoadAttempted_;
        localLoadAttempted_ = true;
    }

    if (shouldLoad) {
        static_cast<void>(LoadLocalDatabase());
    }
}

[[nodiscard]] long AntivirusService::EnsureLoaded(SessionManager& sessionManager)
{
    Start(sessionManager);

    {
        CriticalSectionLock lock(lock_);
        const AntivirusDatabaseInfo info = database_.GetInfo();
        if (info.loaded && !forceDatabaseUpdate_) {
            return rpc_result::kOk;
        }
    }

    const long reloadResult = Reload(sessionManager);
    {
        CriticalSectionLock lock(lock_);
        return database_.GetInfo().loaded ? rpc_result::kOk : reloadResult;
    }
}

[[nodiscard]] long AntivirusService::Reload(SessionManager& sessionManager)
{
    std::vector<std::uint8_t> packageData;
    const long downloadResult = sessionManager.DownloadSignatureDatabase(packageData);
    if (downloadResult != rpc_result::kOk) {
        return downloadResult;
    }

    return InstallDownloadedPackage(packageData, &sessionManager);
}

[[nodiscard]] AntivirusDatabaseInfo AntivirusService::GetDatabaseInfo() const
{
    CriticalSectionLock lock(lock_);
    return database_.GetInfo();
}

[[nodiscard]] long AntivirusService::ScanFile(
    SessionManager& sessionManager,
    const std::wstring& path,
    std::vector<ScanResult>& results
)
{
    const long loadResult = EnsureLoaded(sessionManager);
    if (loadResult != rpc_result::kOk) {
        return loadResult;
    }

    {
        CriticalSectionLock lock(lock_);
        results.clear();
        AppendFileScan(database_, path, results);
    }
    return rpc_result::kOk;
}

[[nodiscard]] long AntivirusService::ScanDirectory(
    SessionManager& sessionManager,
    const std::wstring& path,
    std::vector<ScanResult>& results
)
{
    const long loadResult = EnsureLoaded(sessionManager);
    if (loadResult != rpc_result::kOk) {
        return loadResult;
    }

    {
        CriticalSectionLock lock(lock_);
        results.clear();
        AppendDirectoryScan(database_, path, results);
        LimitResults(results);
    }
    return rpc_result::kOk;
}

[[nodiscard]] long AntivirusService::ScanFixedDrives(SessionManager& sessionManager, std::vector<ScanResult>& results)
{
    const long loadResult = EnsureLoaded(sessionManager);
    if (loadResult != rpc_result::kOk) {
        return loadResult;
    }

    {
        CriticalSectionLock lock(lock_);
        results.clear();
        for (const std::wstring& drive : FixedDriveRoots()) {
            AppendDirectoryScan(database_, drive, results);
            if (results.size() >= kMaxResults) {
                break;
            }
        }
        LimitResults(results);
    }
    return rpc_result::kOk;
}

[[nodiscard]] long AntivirusService::ConfigureSchedule(
    SessionManager& sessionManager,
    ScanTargetType targetType,
    const std::wstring& path,
    std::uint32_t intervalMinutes
)
{
    if (intervalMinutes == 0) {
        StopScheduleThread();
        return rpc_result::kOk;
    }

    const long loadResult = EnsureLoaded(sessionManager);
    if (loadResult != rpc_result::kOk) {
        return loadResult;
    }

    StopScheduleThread();
    {
        CriticalSectionLock lock(lock_);
        sessionManager_ = &sessionManager;
        scheduleTargetType_ = targetType;
        schedulePath_ = path;
        scheduleIntervalMinutes_ = intervalMinutes;
        scheduledResults_.clear();
    }

    ResetEvent(scheduleStopEvent_);
    scheduleThread_ = CreateThread(nullptr, 0, ScheduleProc, this, 0, nullptr);
    return scheduleThread_ != nullptr ? rpc_result::kOk : rpc_result::kInternalError;
}

[[nodiscard]] long AntivirusService::ConfigureMonitoring(SessionManager& sessionManager, const std::wstring& path)
{
    if (path.empty()) {
        StopMonitorThread();
        return rpc_result::kOk;
    }

    const long loadResult = EnsureLoaded(sessionManager);
    if (loadResult != rpc_result::kOk) {
        return loadResult;
    }

    StopMonitorThread();
    {
        CriticalSectionLock lock(lock_);
        sessionManager_ = &sessionManager;
        monitoredPath_ = path;
        monitoringResults_.clear();
    }

    ResetEvent(monitorStopEvent_);
    monitorThread_ = CreateThread(nullptr, 0, MonitorProc, this, 0, nullptr);
    return monitorThread_ != nullptr ? rpc_result::kOk : rpc_result::kInternalError;
}

[[nodiscard]] std::vector<ScanResult> AntivirusService::GetScheduledResults() const
{
    CriticalSectionLock lock(lock_);
    return scheduledResults_;
}

[[nodiscard]] std::vector<ScanResult> AntivirusService::GetMonitoringResults() const
{
    CriticalSectionLock lock(lock_);
    return monitoringResults_;
}

DWORD WINAPI AntivirusService::ScheduleProc(void* context)
{
    static_cast<AntivirusService*>(context)->ScheduleLoop();
    return 0;
}

DWORD WINAPI AntivirusService::MonitorProc(void* context)
{
    static_cast<AntivirusService*>(context)->MonitorLoop();
    return 0;
}

DWORD WINAPI AntivirusService::DatabaseUpdateProc(void* context)
{
    static_cast<AntivirusService*>(context)->DatabaseUpdateLoop();
    return 0;
}

void AntivirusService::StartDatabaseUpdateThread(SessionManager& sessionManager)
{
    {
        CriticalSectionLock lock(lock_);
        databaseSessionManager_ = &sessionManager;
        if (databaseUpdateThread_ != nullptr || databaseUpdateStopEvent_ == nullptr) {
            return;
        }
    }

    ResetEvent(databaseUpdateStopEvent_);
    HANDLE thread = CreateThread(nullptr, 0, DatabaseUpdateProc, this, 0, nullptr);
    if (thread == nullptr) {
        return;
    }

    CriticalSectionLock lock(lock_);
    if (databaseUpdateThread_ == nullptr) {
        databaseUpdateThread_ = thread;
    } else {
        CloseHandle(thread);
    }
}

void AntivirusService::ScheduleLoop()
{
    for (;;) {
        SessionManager* manager = nullptr;
        ScanTargetType targetType = ScanTargetType::Directory;
        std::wstring path;
        std::uint32_t intervalMinutes = 0;
        {
            CriticalSectionLock lock(lock_);
            manager = sessionManager_;
            targetType = scheduleTargetType_;
            path = schedulePath_;
            intervalMinutes = scheduleIntervalMinutes_;
        }

        if (manager != nullptr) {
            std::vector<ScanResult> results;
            static_cast<void>(ScanTargetLocked(*manager, targetType, path, results));
            SaveScheduledResults(results);
        }

        const DWORD waitMs = intervalMinutes == 0 ? INFINITE : intervalMinutes * 60U * 1000U;
        if (WaitForSingleObject(scheduleStopEvent_, waitMs) == WAIT_OBJECT_0) {
            return;
        }
    }
}

void AntivirusService::MonitorLoop()
{
    std::wstring directory;
    {
        CriticalSectionLock lock(lock_);
        directory = monitoredPath_;
    }

    UniqueHandle handle(CreateFileW(
        directory.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    ));
    if (!handle) {
        ScanResult result;
        result.path = directory;
        result.error = L"Не удалось включить мониторинг";
        SaveMonitoringResults({result});
        return;
    }

    std::vector<std::uint8_t> buffer(64 * 1024);
    for (;;) {
        OVERLAPPED overlapped = {};
        UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event) {
            return;
        }
        overlapped.hEvent = event.Get();

        DWORD bytesReturned = 0;
        const BOOL started = ReadDirectoryChangesW(
            handle.Get(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            nullptr,
            &overlapped,
            nullptr
        );
        if (!started && GetLastError() != ERROR_IO_PENDING) {
            return;
        }

        HANDLE waits[] = { monitorStopEvent_, event.Get() };
        DWORD waitResult = WaitForMultipleObjects(ARRAYSIZE(waits), waits, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            CancelIo(handle.Get());
            return;
        }

        if (!GetOverlappedResult(handle.Get(), &overlapped, &bytesReturned, FALSE) || bytesReturned == 0) {
            continue;
        }

        std::vector<ScanResult> results;
        std::size_t offset = 0;
        for (;;) {
            auto* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data() + offset);
            const std::wstring filename(info->FileName, info->FileNameLength / sizeof(wchar_t));
            if (info->Action == FILE_ACTION_ADDED ||
                info->Action == FILE_ACTION_MODIFIED ||
                info->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                SessionManager* manager = nullptr;
                {
                    CriticalSectionLock lock(lock_);
                    manager = sessionManager_;
                }
                if (manager != nullptr) {
                    std::vector<ScanResult> single;
                    static_cast<void>(ScanFile(*manager, JoinPath(directory, filename), single));
                    results.insert(results.end(), single.begin(), single.end());
                    LimitResults(results);
                }
            }
            if (info->NextEntryOffset == 0 || results.size() >= kMaxResults) {
                break;
            }
            offset += info->NextEntryOffset;
        }
        if (!results.empty()) {
            SaveMonitoringResults(results);
        }
    }
}

void AntivirusService::DatabaseUpdateLoop()
{
    for (;;) {
        if (WaitForSingleObject(databaseUpdateStopEvent_, kDatabaseUpdateIntervalSeconds * 1000U) == WAIT_OBJECT_0) {
            return;
        }

        SessionManager* manager = nullptr;
        {
            CriticalSectionLock lock(lock_);
            manager = databaseSessionManager_;
        }

        if (manager != nullptr) {
            static_cast<void>(UpdateDatabase(*manager));
        }
    }
}

void AntivirusService::StopScheduleThread()
{
    if (scheduleThread_ == nullptr) {
        return;
    }
    SetEvent(scheduleStopEvent_);
    WaitForSingleObject(scheduleThread_, 5000);
    CloseHandle(scheduleThread_);
    scheduleThread_ = nullptr;
}

void AntivirusService::StopMonitorThread()
{
    if (monitorThread_ == nullptr) {
        return;
    }
    SetEvent(monitorStopEvent_);
    WaitForSingleObject(monitorThread_, 5000);
    CloseHandle(monitorThread_);
    monitorThread_ = nullptr;
}

void AntivirusService::StopDatabaseUpdateThread()
{
    if (databaseUpdateThread_ == nullptr) {
        return;
    }
    SetEvent(databaseUpdateStopEvent_);
    WaitForSingleObject(databaseUpdateThread_, 5000);
    CloseHandle(databaseUpdateThread_);
    databaseUpdateThread_ = nullptr;
}

void AntivirusService::SaveScheduledResults(const std::vector<ScanResult>& results)
{
    CriticalSectionLock lock(lock_);
    scheduledResults_ = results;
}

void AntivirusService::SaveMonitoringResults(const std::vector<ScanResult>& results)
{
    CriticalSectionLock lock(lock_);
    monitoringResults_ = results;
}

[[nodiscard]] long AntivirusService::LoadLocalDatabase()
{
    std::vector<std::uint8_t> packageData;
    if (ReadAllBytes(MainDatabasePath(), packageData) && LoadPackage(packageData, nullptr) == rpc_result::kOk) {
        return rpc_result::kOk;
    }

    if (ReadAllBytes(BackupDatabasePath(), packageData) && LoadPackage(packageData, nullptr) == rpc_result::kOk) {
        CopyIfExists(BackupDatabasePath(), MainDatabasePath());
        return rpc_result::kOk;
    }

    if (ReadAllBytes(DefaultDatabasePath(), packageData) && LoadPackage(packageData, nullptr) == rpc_result::kOk) {
        static_cast<void>(WriteAllBytes(MainDatabasePath(), packageData));
        CriticalSectionLock lock(lock_);
        forceDatabaseUpdate_ = true;
        return rpc_result::kOk;
    }

    return rpc_result::kInvalidServerResponse;
}

[[nodiscard]] long AntivirusService::LoadPackage(
    const std::vector<std::uint8_t>& packageData,
    SessionManager* sessionManager
)
{
    AntivirusDatabase database;
    const AntivirusDatabaseLoadStatus status = database.LoadRawPackage(packageData, CertificatePath(), true);
    if (status != AntivirusDatabaseLoadStatus::Ok) {
        if (status == AntivirusDatabaseLoadStatus::InvalidManifestSignature) {
            CriticalSectionLock lock(lock_);
            forceDatabaseUpdate_ = true;
        }
        return rpc_result::kInvalidServerResponse;
    }

    const std::vector<std::string> invalidRecordIds = database.InvalidRecordIds();
    if (sessionManager != nullptr && !invalidRecordIds.empty()) {
        std::vector<std::uint8_t> repairedPackage;
        if (sessionManager->DownloadSignatureRecords(invalidRecordIds, repairedPackage) == rpc_result::kOk) {
            AntivirusDatabase repairedDatabase;
            if (repairedDatabase.LoadRawPackage(repairedPackage, CertificatePath(), true) == AntivirusDatabaseLoadStatus::Ok &&
                repairedDatabase.GetInfo().recordCount > 0) {
                database.MergeFrom(repairedDatabase);
            }
        }
    }

    {
        CriticalSectionLock lock(lock_);
        database_ = std::move(database);
        lastDatabaseLoadUnixSeconds_ = NowUnixSeconds();
    }
    return rpc_result::kOk;
}

[[nodiscard]] long AntivirusService::InstallDownloadedPackage(
    const std::vector<std::uint8_t>& packageData,
    SessionManager* sessionManager
)
{
    CopyIfExists(MainDatabasePath(), BackupDatabasePath());

    const std::wstring temporaryPath = TemporaryDatabasePath();
    if (!WriteAllBytes(temporaryPath, packageData)) {
        return rpc_result::kInternalError;
    }

    const long loadResult = LoadPackage(packageData, sessionManager);
    if (loadResult != rpc_result::kOk) {
        CopyIfExists(BackupDatabasePath(), MainDatabasePath());
        std::vector<std::uint8_t> backupData;
        if (ReadAllBytes(BackupDatabasePath(), backupData)) {
            static_cast<void>(LoadPackage(backupData, nullptr));
        }
        return loadResult;
    }

    if (!ReplaceFileWith(temporaryPath, MainDatabasePath())) {
        return rpc_result::kInternalError;
    }

    {
        CriticalSectionLock lock(lock_);
        forceDatabaseUpdate_ = false;
    }

    return rpc_result::kOk;
}

[[nodiscard]] long AntivirusService::UpdateDatabase(SessionManager& sessionManager)
{
    std::vector<std::uint8_t> packageData;
    const long downloadResult = sessionManager.DownloadSignatureDatabase(packageData);
    if (downloadResult != rpc_result::kOk) {
        return downloadResult;
    }
    return InstallDownloadedPackage(packageData, &sessionManager);
}

[[nodiscard]] long AntivirusService::ScanTargetLocked(
    SessionManager& sessionManager,
    ScanTargetType targetType,
    const std::wstring& path,
    std::vector<ScanResult>& results
)
{
    switch (targetType) {
    case ScanTargetType::File:
        return ScanFile(sessionManager, path, results);
    case ScanTargetType::Directory:
        return ScanDirectory(sessionManager, path, results);
    case ScanTargetType::FixedDrives:
        return ScanFixedDrives(sessionManager, results);
    default:
        return rpc_result::kInternalError;
    }
}

}
