#ifndef _TEECHAIN_H_
#define _TEECHAIN_H_

#include "message.h"

void teechain_init();
int ecall_primary();
int ecall_setup_deposits(setup_deposits_msg_t msg);

#define MAX_ECALL_RETURN_LENGTH 10000 // 10 KB is max message length across network

#endif /* _TEECHAIN_H_ */