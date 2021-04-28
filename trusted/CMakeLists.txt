add_executable(trusted_teechain.riscv
    cmd_parser.c
    state.c
    teechain.c
    edge_wrapper.c
    channel.c
    map.c
    utils.c
    tinyprintf.c
    debug.c)

include_directories(include
  ${KEYSTONE_SDK_DIR}/include/app)

target_link_libraries(trusted_teechain.riscv
  ${KEYSTONE_LIB_EDGE}
  ${KEYSTONE_LIB_EAPP}
  ${LIBSODIUM_DIR}/.libs/libsodium.a
  ${LIBBTC_DIR}/.libs/libbtc.a
  ${LIBBTC_DIR}/src/secp256k1/.libs/libsecp256k1.a)

set_target_properties(trusted_teechain.riscv
  PROPERTIES LINK_FLAGS "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")
