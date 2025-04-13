cmake_minimum_required(VERSION 3.21)

set(CMAKE_EXPORT_COMPILE_COMMANDS true)

# option(ARCH "Target architecture") <- See CMakePresets.json for build options

project(qr_tool LANGUAGES C VERSION 1.0 DESCRIPTION "Command line QR encoder")

# https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
# Requires GCC 13.0.0: -fstrict-flex-arrays=3
set(BASE_COMPILER_OPTIONS -O2 -Wall -Wextra -Wshadow -Werror -Wpedantic -Winline -Wformat -Wformat=2 -Wconversion -Wimplicit-fallthrough -Werror=format-security -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS  -fstack-clash-protection -fstack-protector-strong)
set(BASE_LINKER_OPTIONS -Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--no-copy-dt-needed-entries)
set(PROD_OPTIONS -fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing -ftrivial-auto-var-init=zero)
set(C_OPTIONS -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion)
set(EXEC_OPTIONS -fPIE -pie)
set(SHARED_OPTIONS -fPIC -shared)
# set(THREAD_OPTIONS -fexceptions)

message("Target: ${CMAKE_SYSTEM_PROCESSOR} Compiler: ${CMAKE_C_COMPILER_ID}")
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(x86_64_OPTIONS -fcf-protection=full)
endif()
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(aarch64_OPTIONS -mbranch-protection=standard)
endif()
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(GCC_OPTIONS -Wtrampolines)
endif()

add_subdirectory(src)

list(APPEND SOURCE_FILES main.c)

add_executable(qr)
target_compile_options(qr PRIVATE ${BASE_COMPILER_OPTIONS} ${PROD_OPTIONS} ${C_OPTIONS})
target_link_options(qr PRIVATE ${BASE_LINKER_OPTIONS})
target_include_directories(qr PRIVATE ./include)
target_sources(qr PRIVATE ${SOURCE_FILES})
target_link_libraries(qr qr_encoder)
set_target_properties(qr PROPERTIES C_STANDARD 17)

install(TARGETS qr DESTINATION build/bin)

if(BUILD_UNIT_TESTS)
add_subdirectory(test)
endif()