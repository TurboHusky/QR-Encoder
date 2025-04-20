cmake_minimum_required(VERSION 3.21)

project(qr_tests LANGUAGES C VERSION 0.0.1 DESCRIPTION "Unit tests for QR encoder")

set(WITH_EXAMPLES OFF CACHE BOOL "Do not build cmocka examples")
add_subdirectory(cmocka)

add_executable(qr_encoder_tests test_suite.c)

target_compile_options(qr_encoder_tests PRIVATE ${PROJECT_COMPILER_FLAGS}  -fprofile-arcs -ftest-coverage)
target_include_directories(qr_encoder_tests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/cmocka/include)
target_link_options(qr_encoder_tests PRIVATE --coverage)
target_link_libraries(qr_encoder_tests cmocka qr_encoder gcov)
set_target_properties(qr_encoder_tests PROPERTIES VERSION ${PROJECT_VERSION})

if (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    add_custom_command(TARGET gb_sprite_tests POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:gb_sprite_tests> $<TARGET_FILE_DIR:gb_sprite_tests> )
endif()

enable_testing()

add_test(
    NAME qr_encoder_test_suite
    COMMAND $<TARGET_FILE:qr_encoder_tests>
)