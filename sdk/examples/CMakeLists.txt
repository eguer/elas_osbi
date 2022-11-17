enable_language(C CXX ASM)

include(../macros.cmake)
include(ExternalProject)
find_package(Git REQUIRED)

if(RISCV32)
  message(STATUS "riscv32")
  set(BITS 32)
else()
  message(STATUS "riscv64")
  set(BITS 64)
endif()

use_riscv_toolchain_no_werror(${BITS})

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()

set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

# export include directory
#include_directories(AFTER ${KEYSTONE_SDK_DIR}/lib/app/include ${KEYSTONE_SDK_DIR}/lib/edge/include ${KEYSTONE_SDK_DIR}/lib/host/include ${KEYSTONE_SDK_DIR}/lib/verifier/include ${KEYSTONE_SDK_DIR}/lib/app/include ${KEYSTONE_SDK_DIR}/../libsodium/src/libsodium/include)

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)

# find program "makeself"
find_program(MAKESELF makeself)

# create a phony target "examples"
add_custom_target("examples")

# add all examples below
add_subdirectory(hello)
#add_subdirectory(client-server)
#add_subdirectory(hello-native2)
#add_subdirectory(tests)
