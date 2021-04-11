#include "state.h"

// Global state of this enclave
enum TeechanState teechain_state = Ghost;

int check_state(enum TeechanState state) {
    if (teechain_state != state) {
        return -1;
    }
    return 0;
}