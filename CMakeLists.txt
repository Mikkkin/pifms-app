cmake_minimum_required(VERSION 3.20)
project(PIFMSApp VERSION 1.0 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY         ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG   ${CMAKE_BINARY_DIR})

add_executable(PIFMSApp WIN32 src/main.cpp)

target_compile_features(PIFMSApp PRIVATE cxx_std_17)
target_compile_definitions(PIFMSApp PRIVATE UNICODE _UNICODE)

if(MSVC)
    target_compile_options(PIFMSApp PRIVATE /utf-8 /W4 /permissive-)
else()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(PIFMSApp PRIVATE
            -finput-charset=UTF-8
            -fexec-charset=UTF-8
        )
    endif()

    target_compile_options(PIFMSApp PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

target_link_libraries(PIFMSApp PRIVATE shell32 user32)
