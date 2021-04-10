add_executable(trusted_teechain.riscv
    cmd_parser.cpp
    state.c
    teechain.c
    edge_wrapper.c
    channel.c)

include_directories(include
  ${KEYSTONE_SDK_DIR}/include/app)

target_link_libraries(trusted_teechain.riscv
  ${KEYSTONE_LIB_EDGE}
  ${KEYSTONE_LIB_EAPP}
  ${LIBSODIUM_DIR}/.libs/libsodium.a)

set_target_properties(trusted_teechain.riscv
  PROPERTIES LINK_FLAGS "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")
