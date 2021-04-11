#ifndef _COMMAND_H_
#define _COMMAND_H_

#define RES_SUCCESS 0
#define RES_UNKNOWN 1

// command option codes
#define OPT_INIT        (1 << 0)
#define OPT_DEBUG       (1 << 1)
#define OPT_MONOTONIC   (1 << 2)
#define OPT_BENCHMARK   (1 << 3)

#define OP_QUIT 0
#define OP_CMD 1

// ghost assignment message codes
#define OP_PRIMARY 10 // send primary assignment to ghost enclave
#define OP_BACKUP 11 // send backup assignment to ghost enclave


typedef struct CommandMsg {
    // operation
    char msg_op;
    // option
    int msg_opt;
    size_t len;
    char msg[]; // Flexible member
} CommandMsg;

#endif /* _COMMAND_H_ */