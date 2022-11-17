cmake_minimum_required(VERSION 3.5)

set(eapp1_bin client)
set(eapp1_src eapp/client.c)
set(eapp2_bin server)
set(eapp2_src eapp/server.c)
set(host_bin cs-runner)
set(host_src host/host.cpp)
set(package_name "client-server.ke")
set(package_script "./cs-runner client server eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup")
endif()

# eapp

add_executable(${eapp1_bin} ${eapp1_src})
target_link_libraries(${eapp1_bin} PRIVATE
${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE} $ENV{LIBSODIUM_DIR}/.libs/libsodium.a)
target_link_options(${eapp1_bin} BEFORE PRIVATE "-static" "-Wl,--undefined=exit" "-Wl,--allow-multiple-definition")
target_include_directories(${eapp1_bin} PRIVATE
${KEYSTONE_SDK_DIR}/lib/app/include ${KEYSTONE_SDK_DIR}/lib/edge/include ${KEYSTONE_SDK_DIR}/lib/verifier/include ${KEYSTONE_SDK_DIR}/lib/app/include $ENV{LIBSODIUM_DIR}/include)

add_executable(${eapp2_bin} ${eapp2_src})
target_link_libraries(${eapp2_bin} PRIVATE
${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE} $ENV{LIBSODIUM_DIR}/.libs/libsodium.a)
target_link_options(${eapp2_bin} BEFORE PRIVATE "-static" "-Wl,--undefined=exit" "-Wl,--allow-multiple-definition")
target_include_directories(${eapp2_bin} PRIVATE
${KEYSTONE_SDK_DIR}/lib/app/include ${KEYSTONE_SDK_DIR}/lib/edge/include ${KEYSTONE_SDK_DIR}/lib/verifier/include ${KEYSTONE_SDK_DIR}/lib/app/include $ENV{LIBSODIUM_DIR}/include)

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER} pthread)
target_include_directories(${host_bin} PRIVATE
${KEYSTONE_SDK_DIR}/lib/host/include ${KEYSTONE_SDK_DIR}/lib/edge/include ${KEYSTONE_SDK_DIR}/lib/verifier/include)

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp1_bin}-eyrie
  "v1.0.0"
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp1_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp1_bin} ${eapp2_bin} ${host_bin})

add_dependencies(${eapp1_bin}-package ${eapp1_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp1_bin}-package)

