#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#define RES_SUCCESS 0
#define RES_WRONG_STATE 1
#define RES_WRONG_LIBBTC 2

#define OP_QUIT 0

// ghost assignment message codes
#define OP_PRIMARY 10 // send primary assignment to ghost enclave
#define OP_BACKUP 11 // send backup assignment to ghost enclave

// primary setup message codes
#define OP_TEECHAIN_SETUP_DEPOSITS 20 // send local setup deposits to primary
#define OP_TEECHAIN_SETUP 21 // send local setup deposits to primary
#define OP_TEECHAIN_SETUP_TXID 22 // send local setup transaction hash to primary
#define OP_TEECHAIN_DEPOSITS_MADE 23 // send local deposits made message to primary

typedef struct exit_msg_t {
    char msg_op;
} exit_msg_t;

typedef struct assignment_msg_t {
    // operation
    char msg_op;
    char use_monotonic_counters;
} assignment_msg_t;

typedef struct setup_deposits_msg_t {
    char msg_op;
    unsigned long long num_deposits;
} setup_deposits_msg_t;

#endif /* _MESSAGE_H_ */