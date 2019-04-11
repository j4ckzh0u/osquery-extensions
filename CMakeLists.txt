cmake_minimum_required(VERSION 3.12.1)
project(bcc_test)

if("${CMAKE_BUILD_TYPE}" STREQUAL "")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE String "Build type" FORCE)
endif()

function(bccTestMain)
  add_executable("${PROJECT_NAME}"
    src/main.cpp
  )

  importBCC()
  target_link_libraries("${PROJECT_NAME}" PRIVATE thirdparty_bcc)

  add_subdirectory("probes")
  target_link_libraries("${PROJECT_NAME}" PRIVATE execve_probe)

  generateDefaultSettingsTarget()
  target_link_libraries("${PROJECT_NAME}" PUBLIC default_cxx_settings bcc bcc_bpf)
endfunction()

function(generateDefaultSettingsTarget)
  add_library(default_cxx_settings INTERFACE)
  target_compile_features(default_cxx_settings INTERFACE cxx_std_17)

  target_compile_options(default_cxx_settings INTERFACE
    -Wall
    -Wextra
    -Werror
    -Wconversion
    -Wunused
    -Wshadow
    -pedantic
    -fvisibility=hidden
  )

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    target_compile_options(default_cxx_settings INTERFACE -g3)
  endif()

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    target_compile_options(default_cxx_settings INTERFACE -O0)
  endif()
endfunction()

function(importBCC)
  find_path(bcc_include_path "bcc/BPF.h")
  if("${bcc_include_path}" STREQUAL "bcc_include_path-NOTFOUND")
    message(FATAL_ERROR "Failed to locate the BCC include files")
  endif()

  message(STATUS "Found BCC include files: ${bcc_include_path}/bcc")

  find_library(bcc_library_path "libbcc.so")
  if("${bcc_library_path}" STREQUAL "bcc_library_path-NOTFOUND")
    message(FATAL_ERROR "Failed to locate the libbcc.so library")
  endif()

  message(STATUS "Found BCC library: ${bcc_library_path}")

  add_library(bcc SHARED IMPORTED GLOBAL)
  set_target_properties(bcc PROPERTIES
    IMPORTED_LOCATION "${bcc_library_path}"
  )

  find_library(bccbpf_library_path "libbcc_bpf.so")
  if("${bccbpf_library_path}" STREQUAL "bccbpf_library_path-NOTFOUND")
    message(FATAL_ERROR "Failed to locate the libbcc_bpf.so library")
  endif()

  message(STATUS "Found BCC_BPF library: ${bccbpf_library_path}")

  add_library(bcc_bpf SHARED IMPORTED GLOBAL)
  set_target_properties(bcc_bpf PROPERTIES
    IMPORTED_LOCATION "${bccbpf_library_path}"
  )

  

  add_library(thirdparty_bcc INTERFACE)
  target_link_libraries(thirdparty_bcc INTERFACE bcc bcc_bpf)
endfunction()

bccTestMain()
