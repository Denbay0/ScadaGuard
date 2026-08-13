cmake_minimum_required(VERSION 3.25)
project(ScadaGuard VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "ScadaGuard Agent currently supports Windows only")
endif()

option(SCADAGUARD_BUILD_TESTS "Build ScadaGuard tests" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

configure_file(
  include/scadaguard/version.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/generated/scadaguard/version.hpp
  @ONLY
)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(httplib CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(scadaguard_core
  src/model.cpp
    src/configuration/config.cpp
    src/configuration/central_configuration.cpp
  src/checks/checks.cpp
  src/checks/scheduler.cpp
  src/quality/data_quality.cpp
  src/incidents/incident_manager.cpp
  src/collectors/data_sources.cpp
  src/storage/local_storage.cpp
  src/reporting/central_reporter.cpp
  src/http/http_server.cpp
  src/application/application.cpp
  src/discovery/discovery.cpp
  src/discovery/archive_schema_analyzer.cpp
  src/platform/windows/environment.cpp
  src/platform/windows/windows_discovery.cpp
  src/platform/windows/service_host.cpp
)
target_include_directories(scadaguard_core PUBLIC include ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_compile_definitions(scadaguard_core
  PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN
  PUBLIC SCADAGUARD_BUILD_TYPE="$<CONFIG>"
)
target_compile_options(scadaguard_core PRIVATE /W4 /permissive- /EHsc)
target_link_libraries(scadaguard_core
  PUBLIC nlohmann_json::nlohmann_json
  PRIVATE spdlog::spdlog httplib::httplib unofficial::sqlite3::sqlite3
          ws2_32 advapi32 iphlpapi
          OpenSSL::Crypto
          version
)

add_executable(scadaguard src/main.cpp)
target_compile_options(scadaguard PRIVATE /W4 /permissive- /EHsc)
target_link_libraries(scadaguard PRIVATE scadaguard_core spdlog::spdlog)

install(TARGETS scadaguard RUNTIME DESTINATION bin)
install(FILES config/config.example.json DESTINATION config)

if(SCADAGUARD_BUILD_TESTS)
  enable_testing()
  find_package(Catch2 3 CONFIG REQUIRED)
  add_executable(scadaguard_tests
    tests/model_tests.cpp
    tests/config_tests.cpp
    tests/data_quality_tests.cpp
    tests/incident_tests.cpp
    tests/http_state_tests.cpp
    tests/data_source_tests.cpp
    tests/scheduler_tests.cpp
    tests/storage_tests.cpp
    tests/discovery_tests.cpp
  )
  target_compile_options(scadaguard_tests PRIVATE /W4 /permissive- /EHsc)
  target_link_libraries(scadaguard_tests PRIVATE scadaguard_core Catch2::Catch2WithMain)
  include(CTest)
  include(Catch)
  catch_discover_tests(scadaguard_tests)
endif()
