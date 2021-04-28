To run this repo in the qemu, you have to follow these instructions below(you should have built the keystone repo successfully and pass all the tests in qemu)

- `source keystone/source.sh`  to set the environment variables of keystone

- run `./scripts/get_attestation_teechain.sh ./include` to refresh the expected hash code from enclave.

- ```bash
  SM_HASH=<path/to/sm_expected_hash.h> ./quick-start.sh
  ```

- create `teechain/` under `keystone/build/overlay/root` and copy generated binaries into it.

  ```bash
  cp build/enclave-host.riscv build/eyrie-rt build/trusted/trusted_teechain.riscv build/untrusted_teechain.riscv keystone/build/overlay/root/teechain
  ```

- `make`  again, and `./scripts/run-qemu.sh`

- ```bash
  insmod keystone-driver.ko         # load the keystone kernel module (only for newest version)
  ifdown lo && ifup lo              # Setup the loopback device
  cd teechain/
  ./enclave-host.riscv &            # Background the server host
  ./untrusted_teechain.riscv 127.0.0.1
  ```
