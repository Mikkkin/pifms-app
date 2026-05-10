#pragma once

#include "service/antivirus_engine.h"
#include "service/session_manager.h"

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace pifms::service {

class AntivirusService {
public:
    AntivirusService();
    ~AntivirusService();

    AntivirusService(const AntivirusService&) = delete;
    AntivirusService& operator=(const AntivirusService&) = delete;

    [[nodiscard]] long EnsureLoaded(SessionManager& sessionManager);
    [[nodiscard]] long Reload(SessionManager& sessionManager);
    [[nodiscard]] AntivirusDatabaseInfo GetDatabaseInfo() const;
    [[nodiscard]] long ScanFile(SessionManager& sessionManager, const std::wstring& path, std::vector<ScanResult>& results);
    [[nodiscard]] long ScanDirectory(SessionManager& sessionManager, const std::wstring& path, std::vector<ScanResult>& results);
    [[nodiscard]] long ScanFixedDrives(SessionManager& sessionManager, std::vector<ScanResult>& results);
    [[nodiscard]] long ConfigureSchedule(
        SessionManager& sessionManager,
        ScanTargetType targetType,
        const std::wstring& path,
        std::uint32_t intervalMinutes
    );
    [[nodiscard]] long ConfigureMonitoring(SessionManager& sessionManager, const std::wstring& path);
    [[nodiscard]] std::vector<ScanResult> GetScheduledResults() const;
    [[nodiscard]] std::vector<ScanResult> GetMonitoringResults() const;

private:
    static DWORD WINAPI ScheduleProc(void* context);
    static DWORD WINAPI MonitorProc(void* context);

    void ScheduleLoop();
    void MonitorLoop();
    void StopScheduleThread();
    void StopMonitorThread();
    void SaveScheduledResults(const std::vector<ScanResult>& results);
    void SaveMonitoringResults(const std::vector<ScanResult>& results);
    [[nodiscard]] long ScanTargetLocked(
        SessionManager& sessionManager,
        ScanTargetType targetType,
        const std::wstring& path,
        std::vector<ScanResult>& results
    );

    mutable CRITICAL_SECTION lock_ = {};
    AntivirusDatabase database_;
    HANDLE scheduleStopEvent_ = nullptr;
    HANDLE scheduleThread_ = nullptr;
    HANDLE monitorStopEvent_ = nullptr;
    HANDLE monitorThread_ = nullptr;
    std::int64_t lastDatabaseLoadUnixSeconds_ = 0;
    SessionManager* sessionManager_ = nullptr;
    ScanTargetType scheduleTargetType_ = ScanTargetType::Directory;
    std::wstring schedulePath_;
    std::uint32_t scheduleIntervalMinutes_ = 0;
    std::wstring monitoredPath_;
    std::vector<ScanResult> scheduledResults_;
    std::vector<ScanResult> monitoringResults_;
};

}
