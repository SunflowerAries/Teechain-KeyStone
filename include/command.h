#ifndef _COMMAND_H_
#define _COMMAND_H_

// ghost assignment message codes
#define OP_PRIMARY 10 // send primary assignment to ghost enclave
#define OP_BACKUP 11 // send backup assignment to ghost enclave

struct CommandMsg {
    char msg_op[1];
    bool use_monotonic_counters;
};

#endif /* _COMMAND_H_ */