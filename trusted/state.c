#include "state.h"

// Global state of this enclave
enum teechan_state_t teechain_state = Ghost;

int check_state(enum teechan_state_t state) {
    if (teechain_state != state) {
        return -1;
    }
    return 0;
}