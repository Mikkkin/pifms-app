cmake_minimum_required(VERSION 3.20)
project(PIFMSApp VERSION 1.0 LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "PIFMSApp uses Win32 service/RPC APIs and must be built on Windows")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY         ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG   ${CMAKE_BINARY_DIR})

set(PIFMS_MIDL_SEARCH_DIRS)

if(DEFINED ENV{WindowsSDK_ExecutablePath})
    file(TO_CMAKE_PATH "$ENV{WindowsSDK_ExecutablePath}" PIFMS_WINDOWS_SDK_EXECUTABLE_PATH)
    list(APPEND PIFMS_MIDL_SEARCH_DIRS "${PIFMS_WINDOWS_SDK_EXECUTABLE_PATH}")
endif()

set(PIFMS_WINDOWS_SDK_ROOTS)

if(DEFINED ENV{WindowsSdkDir})
    file(TO_CMAKE_PATH "$ENV{WindowsSdkDir}" PIFMS_WINDOWS_SDK_DIR)
    list(APPEND PIFMS_WINDOWS_SDK_ROOTS "${PIFMS_WINDOWS_SDK_DIR}")
endif()

if(DEFINED ENV{ProgramFiles\(x86\)})
    file(TO_CMAKE_PATH "$ENV{ProgramFiles\(x86\)}" PIFMS_PROGRAM_FILES_X86)
    list(APPEND PIFMS_WINDOWS_SDK_ROOTS "${PIFMS_PROGRAM_FILES_X86}/Windows Kits/10")
endif()

list(APPEND PIFMS_WINDOWS_SDK_ROOTS "C:/Program Files (x86)/Windows Kits/10")
list(REMOVE_DUPLICATES PIFMS_WINDOWS_SDK_ROOTS)

set(PIFMS_MIDL_HOST_ARCHES)

foreach(PIFMS_ARCH_VALUE IN ITEMS
        "${CMAKE_HOST_SYSTEM_PROCESSOR}"
        "$ENV{PROCESSOR_ARCHITECTURE}"
        "$ENV{PROCESSOR_ARCHITEW6432}"
        "${CMAKE_VS_PLATFORM_NAME}"
        "arm64"
        "x64"
        "x86")
    if(PIFMS_ARCH_VALUE)
        string(TOLOWER "${PIFMS_ARCH_VALUE}" PIFMS_ARCH_VALUE_LOWER)

        if(PIFMS_ARCH_VALUE_LOWER STREQUAL "amd64")
            set(PIFMS_ARCH_VALUE_LOWER "x64")
        elseif(PIFMS_ARCH_VALUE_LOWER STREQUAL "x86_64")
            set(PIFMS_ARCH_VALUE_LOWER "x64")
        elseif(PIFMS_ARCH_VALUE_LOWER STREQUAL "i386")
            set(PIFMS_ARCH_VALUE_LOWER "x86")
        endif()

        list(APPEND PIFMS_MIDL_HOST_ARCHES "${PIFMS_ARCH_VALUE_LOWER}")
    endif()
endforeach()

list(REMOVE_DUPLICATES PIFMS_MIDL_HOST_ARCHES)

foreach(PIFMS_WINDOWS_SDK_ROOT IN LISTS PIFMS_WINDOWS_SDK_ROOTS)
    set(PIFMS_WINDOWS_SDK_BIN_DIRS)

    if(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION)
        list(APPEND
            PIFMS_WINDOWS_SDK_BIN_DIRS
            "${PIFMS_WINDOWS_SDK_ROOT}/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}"
        )
    endif()

    file(GLOB PIFMS_DISCOVERED_WINDOWS_SDK_BIN_DIRS
        LIST_DIRECTORIES true
        "${PIFMS_WINDOWS_SDK_ROOT}/bin/10.*"
    )

    if(PIFMS_DISCOVERED_WINDOWS_SDK_BIN_DIRS)
        list(SORT PIFMS_DISCOVERED_WINDOWS_SDK_BIN_DIRS COMPARE NATURAL ORDER DESCENDING)
        list(APPEND PIFMS_WINDOWS_SDK_BIN_DIRS ${PIFMS_DISCOVERED_WINDOWS_SDK_BIN_DIRS})
    endif()

    foreach(PIFMS_WINDOWS_SDK_BIN_DIR IN LISTS PIFMS_WINDOWS_SDK_BIN_DIRS)
        foreach(PIFMS_MIDL_HOST_ARCH IN LISTS PIFMS_MIDL_HOST_ARCHES)
            list(APPEND PIFMS_MIDL_SEARCH_DIRS "${PIFMS_WINDOWS_SDK_BIN_DIR}/${PIFMS_MIDL_HOST_ARCH}")
        endforeach()

        list(APPEND PIFMS_MIDL_SEARCH_DIRS "${PIFMS_WINDOWS_SDK_BIN_DIR}")
    endforeach()
endforeach()

list(REMOVE_DUPLICATES PIFMS_MIDL_SEARCH_DIRS)

find_program(MIDL_EXECUTABLE
    NAMES midl.exe midl
    HINTS ${PIFMS_MIDL_SEARCH_DIRS}
    REQUIRED
)

message(STATUS "Using MIDL: ${MIDL_EXECUTABLE}")

set(PIFMS_TARGET_ARCH "")

if(CMAKE_VS_PLATFORM_NAME)
    string(TOLOWER "${CMAKE_VS_PLATFORM_NAME}" PIFMS_TARGET_ARCH)
elseif(CMAKE_GENERATOR_PLATFORM)
    string(TOLOWER "${CMAKE_GENERATOR_PLATFORM}" PIFMS_TARGET_ARCH)
elseif(CMAKE_SYSTEM_PROCESSOR)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" PIFMS_TARGET_ARCH)
endif()

if(PIFMS_TARGET_ARCH STREQUAL "arm64")
    set(PIFMS_MIDL_ENV arm64)
elseif(PIFMS_TARGET_ARCH STREQUAL "x64" OR
       PIFMS_TARGET_ARCH STREQUAL "amd64" OR
       PIFMS_TARGET_ARCH STREQUAL "x86_64")
    set(PIFMS_MIDL_ENV amd64)
elseif(PIFMS_TARGET_ARCH STREQUAL "win32" OR
       PIFMS_TARGET_ARCH STREQUAL "x86" OR
       PIFMS_TARGET_ARCH STREQUAL "i386")
    set(PIFMS_MIDL_ENV win32)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PIFMS_MIDL_ENV amd64)
else()
    set(PIFMS_MIDL_ENV win32)
endif()

message(STATUS "Using MIDL target env: ${PIFMS_MIDL_ENV}")

set(PIFMS_RPC_IDL ${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/pifms_control.idl)
set(PIFMS_RPC_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/rpc)
set(PIFMS_RPC_HEADER ${PIFMS_RPC_GENERATED_DIR}/pifms_control.h)
set(PIFMS_RPC_CLIENT_STUB ${PIFMS_RPC_GENERATED_DIR}/pifms_control_c.c)
set(PIFMS_RPC_SERVER_STUB ${PIFMS_RPC_GENERATED_DIR}/pifms_control_s.c)

add_custom_command(
    OUTPUT
        ${PIFMS_RPC_HEADER}
        ${PIFMS_RPC_CLIENT_STUB}
        ${PIFMS_RPC_SERVER_STUB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PIFMS_RPC_GENERATED_DIR}
    COMMAND ${MIDL_EXECUTABLE}
        /nologo
        /char signed
        /env ${PIFMS_MIDL_ENV}
        /out ${PIFMS_RPC_GENERATED_DIR}
        /h pifms_control.h
        /client stub
        /server stub
        ${PIFMS_RPC_IDL}
    DEPENDS ${PIFMS_RPC_IDL}
    VERBATIM
)

set_source_files_properties(
    ${PIFMS_RPC_HEADER}
    ${PIFMS_RPC_CLIENT_STUB}
    ${PIFMS_RPC_SERVER_STUB}
    PROPERTIES
        GENERATED TRUE
        LANGUAGE C
)

add_custom_target(PIFMSRpcGenerated
    DEPENDS
        ${PIFMS_RPC_HEADER}
        ${PIFMS_RPC_CLIENT_STUB}
        ${PIFMS_RPC_SERVER_STUB}
)

add_library(PIFMSRpcClientStub STATIC ${PIFMS_RPC_CLIENT_STUB})
add_library(PIFMSRpcServerStub STATIC ${PIFMS_RPC_SERVER_STUB})

add_dependencies(PIFMSRpcClientStub PIFMSRpcGenerated)
add_dependencies(PIFMSRpcServerStub PIFMSRpcGenerated)

target_include_directories(PIFMSRpcClientStub PRIVATE ${PIFMS_RPC_GENERATED_DIR})
target_include_directories(PIFMSRpcServerStub PRIVATE ${PIFMS_RPC_GENERATED_DIR})
target_compile_definitions(PIFMSRpcClientStub PRIVATE UNICODE _UNICODE)
target_compile_definitions(PIFMSRpcServerStub PRIVATE UNICODE _UNICODE)

add_executable(PIFMSApp WIN32
    src/main.cpp
    src/gui/rpc_client.cpp
    src/gui/service_guard.cpp
)

add_executable(PIFMSService WIN32
    src/service/service_main.cpp
    src/service/antivirus_engine.cpp
    src/service/antivirus_service.cpp
    src/common/device_info.cpp
    src/common/text_utils.cpp
    src/service/api_client.cpp
    src/service/session_manager.cpp
)

add_executable(PIFMSAntivirusEngine
    src/tests/antivirus_engine_tests.cpp
    src/service/antivirus_engine.cpp
    src/common/text_utils.cpp
)

add_dependencies(PIFMSApp PIFMSRpcClientStub)
add_dependencies(PIFMSService PIFMSRpcServerStub)

target_include_directories(PIFMSApp PRIVATE
    src
    ${PIFMS_RPC_GENERATED_DIR}
)

target_include_directories(PIFMSService PRIVATE
    src
    ${PIFMS_RPC_GENERATED_DIR}
)

target_include_directories(PIFMSAntivirusEngine PRIVATE
    src
)

target_compile_features(PIFMSApp PRIVATE cxx_std_17)
target_compile_features(PIFMSService PRIVATE cxx_std_17)
target_compile_features(PIFMSAntivirusEngine PRIVATE cxx_std_17)
target_compile_definitions(PIFMSApp PRIVATE UNICODE _UNICODE NOMINMAX _WIN32_WINNT=0x0601)
target_compile_definitions(PIFMSService PRIVATE UNICODE _UNICODE NOMINMAX _WIN32_WINNT=0x0601)
target_compile_definitions(PIFMSAntivirusEngine PRIVATE UNICODE _UNICODE NOMINMAX _WIN32_WINNT=0x0601)

if(MSVC)
    target_compile_options(PIFMSApp PRIVATE /utf-8 /W4 /permissive-)
    target_compile_options(PIFMSService PRIVATE /utf-8 /W4 /permissive-)
    target_compile_options(PIFMSAntivirusEngine PRIVATE /utf-8 /W4 /permissive-)
else()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(PIFMSApp PRIVATE
            -finput-charset=UTF-8
            -fexec-charset=UTF-8
        )
        target_compile_options(PIFMSService PRIVATE
            -finput-charset=UTF-8
            -fexec-charset=UTF-8
        )
        target_compile_options(PIFMSAntivirusEngine PRIVATE
            -finput-charset=UTF-8
            -fexec-charset=UTF-8
        )
    endif()

    target_compile_options(PIFMSApp PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
    target_compile_options(PIFMSService PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
    target_compile_options(PIFMSAntivirusEngine PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

target_link_libraries(PIFMSApp PRIVATE PIFMSRpcClientStub advapi32 comdlg32 ole32 rpcrt4 shell32 user32)
target_link_libraries(PIFMSService PRIVATE PIFMSRpcServerStub advapi32 crypt32 iphlpapi rpcrt4 userenv winhttp wtsapi32)
target_link_libraries(PIFMSAntivirusEngine PRIVATE crypt32)
