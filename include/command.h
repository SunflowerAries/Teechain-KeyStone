#ifndef _COMMAND_H_
#define _COMMAND_H_

#define OP_QUIT 0
#define OP_CMD 1

// ghost assignment message codes
#define OP_PRIMARY 10 // send primary assignment to ghost enclave
#define OP_BACKUP 11 // send backup assignment to ghost enclave


struct CommandMsg {
    char msg_op;
    size_t len;
    char msg[]; // Flexible member
};

#endif /* _COMMAND_H_ */