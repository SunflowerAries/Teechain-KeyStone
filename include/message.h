#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#define RES_SUCCESS 0
#define RES_WRONG_STATE 1

#define OP_QUIT 0

// ghost assignment message codes
#define OP_PRIMARY 10 // send primary assignment to ghost enclave
#define OP_BACKUP 11 // send backup assignment to ghost enclave

typedef struct ExitMsg {
    char msg_op;
} ExitMsg;

typedef struct AssignmentMsg {
    // operation
    char msg_op;
    char use_monotonic_counters;
} AssignmentMsg;

typedef struct SetupDepositsMsg {
    char msg_op;
    unsigned long long num_deposits;
} SetupDepositsMsg;

#endif /* _MESSAGE_H_ */