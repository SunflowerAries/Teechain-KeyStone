#include "teechain.h"
#include "state.h"
#include "edge_wrapper.h"
#include "message.h"

int ecall_primary() {
    if (check_state(Ghost) != 0) {
        ocall_print_buffer("Cannot assign this node as primary; not in the correct state!\n");
        return RES_WRONG_STATE;
    }
    teechain_state = Primary;
    ocall_print_buffer("Your Enclave has been made into a Primary Teechain node!\n"
        "To use it, please fund your enclave by setting up your funding deposits!\n");
    return RES_SUCCESS;
}