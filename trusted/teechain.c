#include "teechain.h"
#include "state.h"
#include "edge_wrapper.h"

int ecall_primary() {
    if (check_state(Ghost) != 0) {
        ocall_print_buffer("[TT]Cannot assign this node as primary; not in the correct state!\n");
        return -1;
    }
    teechain_state = Primary;
    ocall_print_buffer("Your Enclave has been made into a Primary Teechain node!\n"
        "To use it, please fund your enclave by setting up your funding deposits!\n");
    return 0;
}