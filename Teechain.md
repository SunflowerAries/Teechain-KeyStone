To run this repo in the qemu, you have to follow these instructions below(you should have built the keystone repo successfully and pass all the tests in qemu)

- `source keystone/source.sh`  to set the environment variables of keystone
- run `./scripts/get_attestation.sh ./include` to refresh the expected hash code from enclave.

- ```bash
  SM_HASH=<path/to/sm_expected_hash.h> ./quick-start.sh
  ```

- create `keystone-demo/` under `keystone/build/overlay/root` and copy generated binaries into it.

  ```bash
  cp build/demo-server.riscv build/eyrie-rt build/server_eapp/server_eapp.eapp_riscv build/trusted_client.riscv keystone/build/overlay/root/keystone-demo
  ```

- `make`  again, and `./scripts/run-qemu.sh`