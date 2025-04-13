cmake_minimum_required(VERSION 3.21)

set (CMAKE_EXPORT_COMPILE_COMMANDS true)

project(qr_encoder LANGUAGES C VERSION 0.0.1 DESCRIPTION "QR Encoder")
# Output directories configured in CMakePresets.json

list(APPEND LIB_SOURCE_FILES qr.c)

if(BUILD_SHARED_LIBS)
add_compile_options(-Wl,-rpath,${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(LIB_TYPE "SHARED")
else()
set(LIB_TYPE "STATIC")
endif()

add_library(qr_encoder ${LIB_TYPE})
target_compile_options(qr_encoder PRIVATE ${BASE_COMPILER_OPTIONS} ${PROD_OPTIONS} ${C_OPTIONS})
target_link_options(qr_encoder PRIVATE ${BASE_LINKER_OPTIONS})
target_include_directories(qr_encoder PRIVATE ../include)
target_sources(qr_encoder PRIVATE ${LIB_SOURCE_FILES})
set_target_properties(qr_encoder PROPERTIES VERSION ${PROJECT_VERSION} C_STANDARD 17 PUBLIC_HEADER ../include/qr.h)

install(TARGETS qr_encoder LIBRARY DESTINATION ../build/bin PUBLIC_HEADER DESTINATION ../build/include)