cmake_minimum_required(VERSION 3.22)
cmake_policy(VERSION 3.16)

project(rlbox_lfi
        VERSION 0.1
        DESCRIPTION "RLBox integration with libraries compiled with LFI")

# Project Settings ###################

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
enable_language(C CXX ASM)

option(DEV "Use settings suitable for dev contributions to rlbox" OFF)

file(GLOB_RECURSE
     ALL_CXX_SOURCE_FILES
     ${CMAKE_SOURCE_DIR}/include/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/include/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/include/*.cc
     ${CMAKE_SOURCE_DIR}/include/*.hh
     ${CMAKE_SOURCE_DIR}/include/*.ii
     ${CMAKE_SOURCE_DIR}/include/*.[CHI]
     ${CMAKE_SOURCE_DIR}/test/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/test/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/test/*.cc
     ${CMAKE_SOURCE_DIR}/test/*.hh
     ${CMAKE_SOURCE_DIR}/test/*.ii
     ${CMAKE_SOURCE_DIR}/test/*.[CHI]
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/c_src/*.cc
     ${CMAKE_SOURCE_DIR}/c_src/*.hh
     ${CMAKE_SOURCE_DIR}/c_src/*.ii
     ${CMAKE_SOURCE_DIR}/c_src/*.[CHI])

# Dev Tools ###################

if(DEV)
  find_program(CLANG_TIDY "clang-tidy")
  if(CLANG_TIDY)
    # Config in .clang-tidy
    set(CMAKE_CXX_CLANG_TIDY clang-tidy)
  endif()

  find_program(CLANG_FORMAT "clang-format")
  if(CLANG_FORMAT)
    # Config in .clang-format
    add_custom_target(format-source
                      COMMAND clang-format
                              -i
                              -style=file
                              ${ALL_CXX_SOURCE_FILES})
  endif()

endif()

# Dependencies ###################

find_program(MESON "meson")
if(!MESON)
  message(FATAL_ERROR "Could not find meson. Please install meson.")
endif()

find_program(NINJA "ninja")
if(!NINJA)
  message(FATAL_ERROR "Could not find ninja. Please install ninja.")
endif()

include(FetchContent)

FetchContent_Declare(rlbox
  GIT_REPOSITORY https://github.com/PLSysSec/rlbox.git)
FetchContent_GetProperties(rlbox)
if(NOT rlbox_POPULATED)
  FetchContent_Populate(rlbox)
endif()

FetchContent_Declare(catch2
                     GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                     GIT_TAG v2.13.9)
FetchContent_GetProperties(catch2)
if(NOT catch2_POPULATED)
  FetchContent_Populate(catch2)
endif()

add_subdirectory("${catch2_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/contrib")

FetchContent_Declare(
  lfi
  GIT_REPOSITORY https://github.com/zyedidia/lfi.git
  GIT_TAG update-lfi-ret)
FetchContent_GetProperties(lfi)
if(NOT lfi_POPULATED)
  FetchContent_Populate(lfi)
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  if (${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES "x86_64")
    set (lfi-clang-url https://github.com/zyedidia/lfi/releases/download/v0.7/x86_64-lfi-clang.tar.gz)
  else()
    message(FATAL_ERROR "LFI binaries only available for x86_64.")
  endif()
else()
  message(FATAL_ERROR "LFI binaries only available for linux.")
endif()

FetchContent_Declare(
  lficlang
  URL ${lfi-clang-url}
)
FetchContent_GetProperties(lficlang)
if(NOT lficlang_POPULATED)
  FetchContent_Populate(lficlang)
endif()

# set (lficlang_SOURCE_DIR "/media/shr/extradrive1/Code/LibrarySandboxing/lfi-trampoline-demo/x86_64-lfi-clang")

if(DEV)
  if(MSVC)
    set(RLBOX_SANITIZER_COMPILE_FLAGS)
    set(RLBOX_SANITIZER_LINK_FLAGS "")
  else()
    set(RLBOX_SANITIZER_COMPILE_FLAGS -fsanitize=address -fsanitize=undefined)
    set(RLBOX_SANITIZER_LINK_FLAGS -fsanitize=address -fsanitize=undefined)
  endif()
else()
  set(RLBOX_SANITIZER_COMPILE_FLAGS "")
  set(RLBOX_SANITIZER_LINK_FLAGS "")
endif()


if(DEV)
  set(LFI_BUILD_TYPE "debug")
    set(LFI_SBX_BUILD_TYPE_FLAGS -O0)
else()
  if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    # set(LFI_BUILD_TYPE "debug")
    # set(LFI_SBX_BUILD_TYPE_FLAGS -O0)
    set(LFI_BUILD_TYPE "release")
    set(LFI_SBX_BUILD_TYPE_FLAGS -O3)
  elseif ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    set(LFI_BUILD_TYPE "debugoptimized")
    set(LFI_SBX_BUILD_TYPE_FLAGS -O3)
  elseif ("${CMAKE_BUILD_TYPE}" STREQUAL "MinSizeRel")
    set(LFI_BUILD_TYPE "release")
    set(LFI_SBX_BUILD_TYPE_FLAGS -O3)
  else()
    set(LFI_BUILD_TYPE "release")
    set(LFI_SBX_BUILD_TYPE_FLAGS -O3)
  endif()
endif()

# lfi ###################

set(LFI_RUNTIME_DIR_NAME "build-liblfi-${LFI_BUILD_TYPE}")
set(LFI_RUNTIME_DIR "${lfi_SOURCE_DIR}/${LFI_RUNTIME_DIR_NAME}")
set(LIBLFI_PATH ${LFI_RUNTIME_DIR}/liblfi/liblfi.a)

add_custom_command(OUTPUT "${LFI_RUNTIME_DIR}"
                   WORKING_DIRECTORY "${lfi_SOURCE_DIR}"
                   COMMAND meson setup ${LFI_RUNTIME_DIR_NAME} -Dliblfi-only=true --buildtype ${LFI_BUILD_TYPE}
                   COMMENT "Configuring LFI runtime")

add_custom_command(OUTPUT "${LIBLFI_PATH}"
                   WORKING_DIRECTORY "${LFI_RUNTIME_DIR}"
                   DEPENDS ${LFI_RUNTIME_DIR}
                   COMMAND ninja
                   COMMENT "Building LFI runtime")

add_custom_target(genlfi ALL DEPENDS ${LIBLFI_PATH})


if(DEV)
  if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers ${RLBOX_SANITIZER_COMPILE_FLAGS})
    add_link_options(${RLBOX_SANITIZER_LINK_FLAGS})
  endif()
endif()


add_library(liblfi STATIC IMPORTED)
add_dependencies(liblfi "${LIBLFI_PATH}")
set_target_properties(liblfi PROPERTIES
  IMPORTED_LOCATION "${LIBLFI_PATH}"
  INTERFACE_INCLUDE_DIRECTORIES "${lfi_SOURCE_DIR}/liblfi/include"
)

# Sandboxed tests lib ###################

set(INCSTUB_FILENAME "glue_lib_lfi")
set(GLUE_LIB_ELF "${CMAKE_BINARY_DIR}/${INCSTUB_FILENAME}")
set(LFI_SANDBOX_WRAPPER ${CMAKE_SOURCE_DIR}/src/main.s)
set(LFI_RLBOX_RT_SRC "${CMAKE_SOURCE_DIR}/src/trampoline.S" "${CMAKE_SOURCE_DIR}/src/lfi_callback.c")
set(GLUE_LIB_EMBED_SRC "${CMAKE_SOURCE_DIR}/src/incstub.s")
set(GLUE_LIB_EMBED_DEST "${CMAKE_BINARY_DIR}/incstub.s")

add_custom_command(OUTPUT "${GLUE_LIB_ELF}"
                   DEPENDS "${GLUE_LIB_EMBED_SRC}" ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c
                   COMMAND  PATH=$ENV{PATH}:${lficlang_SOURCE_DIR}/lfi-bin
                            ${lficlang_SOURCE_DIR}/bin/clang
                            ${LFI_SBX_BUILD_TYPE_FLAGS}
                            -static-pie
                            -o ${GLUE_LIB_ELF}
                            ${LFI_SANDBOX_WRAPPER}
                            ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c
                   COMMENT "Building lfi sandboxed library")

configure_file(${GLUE_LIB_EMBED_SRC} ${GLUE_LIB_EMBED_DEST})

add_custom_target(genlib ALL DEPENDS ${GLUE_LIB_ELF} ${GLUE_LIB_EMBED_DEST})

# Tests executables ###################

include(CTest)
include(Catch)

find_package(Threads REQUIRED)

add_executable(test_rlbox_glue test/test_lfi_sandbox_glue_main.cpp
                               test/test_lfi_sandbox_glue.cpp
                               ${LFI_RLBOX_RT_SRC}
                               ${GLUE_LIB_EMBED_DEST}
                               )
target_include_directories(test_rlbox_glue PUBLIC ${CMAKE_SOURCE_DIR}/include
                                           PUBLIC ${rlbox_SOURCE_DIR}/code/include
                                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue
                                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib
                                           )
# target_compile_options(test_rlbox_glue PUBLIC -fno-stack-protector)
target_link_libraries(test_rlbox_glue Catch2::Catch2
                                      ${CMAKE_THREAD_LIBS_INIT}
                                      ${CMAKE_DL_LIBS}
                                      liblfi
)

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue rt)
endif()
catch_discover_tests(test_rlbox_glue)

# Shortcuts ###################

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -V)
add_dependencies(check test_rlbox_glue)
