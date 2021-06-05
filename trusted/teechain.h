#ifndef _TEECHAIN_H_
#define _TEECHAIN_H_

#include "message.h"
#include "channel.h"

void teechain_init();
int ecall_primary();
int ecall_setup_deposits(setup_deposits_msg_t* msg);
int ecall_deposits_made(deposits_made_msg_t* msg);
int ecall_create_channel(create_channel_msg_t* msg);
int ecall_verify_deposits(generic_channel_msg_t* msg);
int ecall_remote_channel_connected(generic_channel_msg_t* msg, int remote_sockfd);
int ecall_remote_channel_connected_ack(generic_channel_msg_t* msg);
void ecall_remote_channel_init(channel_state_t* channel_state);
void ecall_remote_channel_init_ack(channel_state_t* channel_state, channel_init_msg_t* msg);
void ecall_remote_verify_deposits_ack(channel_state_t* channel_state);
void send_on_channel(int operation, channel_state_t* channel_state, unsigned char *msg, size_t msg_len);

// Temporary channel handle
#define TEMPORARY_CHANNEL_ID "0000011111111111111111111111111111111111111111111111111111100000"

#define MAX_ECALL_RETURN_LENGTH 10000 // 10 KB is max message length across network

#endif /* _TEECHAIN_H_ */