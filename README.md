# Teechain/KeyStone

[toc]

This repo contains the [Teechain](https://github.com/lsds/Teechain) source code ported to [KeyStone](https://github.com/keystone-enclave/keystone). It includes an eapp which supports attestation and secure channel to connect eapp with users through [libsodium](https://github.com/jedisct1/libsodium) and bitcoin-related functions ported from [libbtc](https://github.com/libbtc/libbtc).

It's going to support these apis below

- [x] primary
- [x] setup_deposits NUMBER_OF_DEPOSITS
- [x] deposits_made RETURN_BTC_ADDRESS FEE_SATOSHI_PER_BYTE NUMBER_OF_DEPOSITS FUNDING_TX_HASH_0 FUNDING_TX_INDEX_0 FUNDING_TX_AMOUNT_0 <REPEATED TX HASH, INDEX AND AMOUNT FOR ALL FUNDING DEPOSITS>
- [x] create_channel [-i -r REMOTE_IP_ADDRESS:REMOTE_PORT_NUMBER]
- [x] verify_deposits CHANNEL_ID
- [x] balance CHANNEL_ID
- [ ] add_deposit CHANNEL_ID DEPOSIT_ID
- [ ] remove_deposit CHANNEL_ID DEPOSIT_ID
- [ ] send CHANNEL_ID AMOUNT
- [ ] settle_channel CHANNEL_ID
- [ ] return_unused_deposits
- [ ] shutdown

## Basics

This system consists of

- Trusted side of Teechain(eapp)
- Enclave host
- Untrusted side of Teechain

### Trusted side

The trusted side is responsible for securing critical information in Teechain network and respond to user's command. The trusted side and untrusted side are connected by a secure channel through libsodium via enclave host.

### Enclave host

The enclave host serves two functions: starting the untrusted side(eapp), and proxying network messages.

### Untrusted side

The untrusted side is a foreground process which receives users' commands and send to the trusted side.

## Attestation

This system requires the expected hash values of the security monitor(sm) and enclave application(eapp), these two hashes will be used by the untrusted side of teechain to verify that the trusted side of teechain is created, initialized by the known SM as expected. These two hashes reside in `include/enclave_expected_hash.h` and `include/sm_expected_hash.h`.

## Migration

### Libsodium

The migration of libsodium totally refers to [keystone-demo](https://github.com/keystone-enclave/keystone-demo)

### Libbtc

The migration of libbtc mainly contains

- Introduce `PRINTF` functions for debugging inside enclave
- Ban some functions of wallet, tools, net and test module due to the incompleteness of the enclave runtime
- rewrite the random number generator

### KeyStone-SDK

This system will utilize some syscall interface such as: *open*, *close*, *read*, so we need register them in sdk(patch based on commit **b660b5f** can be found in patches/0001-add-syscall-interface.patch).

## Quick Start

To run this repo in the qemu, you have to follow these instructions below(you should have cloned and built the keystone repo successfully and passed all the tests in qemu, for more information you can refer to [keystone official website](https://keystone-enclave.org/))

1. Add `export KEYSTONE_DIR=keystone/build` to the `keystone/source.sh`. `source keystone/source.sh` under this repo to set the environment variables of keystone. **For now, you need to create two built image under keystone, i.e., keystone/build, keystone/build0, and add *hostfwd=tcp::XX-:8067* to run-qemu.sh script in keystone/build(0)/scripts to expose port 8067 within qemu, at which the enclave host's socket is listening, to the host's XX port. You can enter *route* within qemu to find the ip host mapped into qemu.**  

   Like below, `192.168.100.2` is mapped into the qemu, so if you setup a node in build(build directory) with 18067 redirected to 8067 and a node in build0 with 8067 redirected to 8067, then you can issue `create_channel -i -r 192.168.100.2 18067` within qemu under build0 to connect to node in build, say go out of the qemu in build0, to the host and then redirect to qemu in build.

   ```
   # route 
   Kernel IP routing table
   Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
   default         192.168.100.2   0.0.0.0         UG    0      0        0 eth0
   192.168.100.0   *               255.255.255.0   U     0      0        0 eth0
   ```

2. `./quick-start.sh` to init the repo, fetching specified version of libsodium and libbtc, if you find that libbtc as submodule has been updated, you can use `git submodule update --remote` to update it.

3. `source ./source.sh` under this repo to set the environment variables.

4. `./build.sh` to build the system, then you'll see the server enclave package `enclave-host.ke`, untrusted side of teechain `untrusted_teechain.riscv` and runtime `eyrie-rt` under `build` directory and trusted side of teechain `trusted_teechain.riscv` under `build/trusted` directory.

5. create `teechain/` under `keystone/build/overlay/root` and copy generated binaries into it.

   ```
   mkdir -p keystone/build/overlay/root/teechain
   cp build/enclave-host.riscv build/eyrie-rt build/trusted/trusted_teechain.riscv build/untrusted_teechain.riscv keystone/build/overlay/root/teechain
   ```

6. `make image` under `keystone/build` to refresh the generated keystone payload for qemu.

7. `./scripts/get_attestation.sh ./include` under this repo to refresh the expected hash values of the eapp code.

8. `./build.sh` with new hash and copy the newly generated binaries to `keystone/build/overlay/root/teechain`

9. `make image` under `keystone/build` again, and `./scripts/run-qemu.sh`

10. ```
      insmod keystone-driver.ko         # load the keystone kernel module (only for newest version)
      ifdown lo && ifup lo              # Setup the loopback device
      cd teechain/
      ./enclave-host.riscv &            # Background the server host
      ./untrusted_teechain.riscv 127.0.0.1
    ```

