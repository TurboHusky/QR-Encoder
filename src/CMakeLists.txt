cmake_minimum_required(VERSION 3.21)

include(GenerateExportHeader)

set (CMAKE_EXPORT_COMPILE_COMMANDS true)

project(qr_encoder LANGUAGES C VERSION 0.0.1 DESCRIPTION "QR Encoder")
# Output directories configured in CMakePresets.json

list(APPEND LIB_SOURCE_FILES qr.c)

if(BUILD_SHARED_LIBS)
set(LIB_TYPE "SHARED")
set(BUILD_RPATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
else()
set(LIB_TYPE "STATIC")
endif()

add_library(qr_encoder ${LIB_TYPE})
set_target_properties(qr_encoder PROPERTIES VERSION ${PROJECT_VERSION} C_STANDARD 17 PUBLIC_HEADER ${CMAKE_SOURCE_DIR}/include/qr.h)

target_compile_options(qr_encoder PRIVATE ${BASE_COMPILER_OPTIONS} ${PROD_OPTIONS} ${C_OPTIONS})
target_link_options(qr_encoder PRIVATE ${BASE_LINKER_OPTIONS})
target_include_directories(qr_encoder PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_sources(qr_encoder PRIVATE ${LIB_SOURCE_FILES})

generate_export_header(qr_encoder)
install(TARGETS qr_encoder LIBRARY DESTINATION ${BUILD_DIR}/bin PUBLIC_HEADER DESTINATION ${BUILD_DIR}/include)
