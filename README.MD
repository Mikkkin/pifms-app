# PIFMS App

## Environment

Перед запуском службы задайте переменные среды:

```powershell
[Environment]::SetEnvironmentVariable("PIFMS_API_BASE_URL", "https://localhost:8443", "Machine")
[Environment]::SetEnvironmentVariable("PIFMS_ALLOW_INSECURE_TLS", "true", "Machine")
[Environment]::SetEnvironmentVariable("PIFMS_PRODUCT_ID", "00000000-0000-0000-0000-000000000000", "Machine")
```

## Служба

Установка и удаление выполняются из каталога сборки от имени администратора:

```powershell
.\PIFMSService.exe /install
Start-Service PIFMSService
.\PIFMSService.exe /uninstall
```

## Сканирование

`PIFMSAntivirusEngine.exe` используется для быстрой проверки ядра сканирования в CI

## Антивирусные базы

Служба хранит базы в `C:\ProgramData\PIFMS\avdb\signatures.pifmsdb`, держит резервную копию `.bak`, при старте проверяет подписи и может восстановиться из поставляемой базы `resources\avdb\default.pifmsdb`. Обновление баз выполняется каждые 5 минут с предварительным резервным копированием.
