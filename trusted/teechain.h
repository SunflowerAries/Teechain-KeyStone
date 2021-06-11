#ifndef _TEECHAIN_H_
#define _TEECHAIN_H_

#include "message.h"
#include "channel.h"

void teechain_init();
int ecall_primary(assignment_msg_t* msg);
int ecall_setup_deposits(setup_deposits_msg_t* msg);
int ecall_deposits_made(deposits_made_msg_t* msg);
int ecall_create_channel(create_channel_msg_t* msg);
int ecall_verify_deposits(generic_channel_msg_t* msg);
int ecall_remote_channel_connected(generic_channel_msg_t* msg, int remote_sockfd);
int ecall_remote_channel_connected_ack(generic_channel_msg_t* msg);
void send_channel_create_data(channel_state_t* channel_state);
void process_channel_create_data(channel_state_t* channel_state, channel_init_msg_t* msg);
void process_verify_deposits_ack(channel_state_t* channel_state);
void send_on_channel(int operation, channel_state_t* channel_state, unsigned char *msg, size_t msg_len);
int ecall_balance(generic_channel_msg_t* msg);
void process_deposit_add(channel_state_t* channel_state, remote_deposit_msg_t* msg);
int ecall_add_deposit_to_channel(deposit_msg_t* msg);
void process_deposit_add_ack(channel_state_t* channel_state, secure_ack_msg_t* msg);
int ecall_remove_deposit_from_channel(deposit_msg_t* msg);
void process_deposit_remove(channel_state_t* channel_state, remote_deposit_msg_t* msg);
void process_deposit_remove_ack(channel_state_t* channel_state, secure_ack_msg_t* msg);
void process_send(channel_state_t* channel_state, remote_send_msg_t* msg);
void process_send_ack(channel_state_t* channel_state);
int ecall_send(send_msg_t* msg);
int ecall_profile();
int ecall_round_trip(send_msg_t* msg);
void process_round_trip0(channel_state_t* channel_state);
void process_round_trip1(channel_state_t* channel_state);
void send_reply(int val);

unsigned long getcycles();

// Temporary channel handle
#define TEMPORARY_CHANNEL_ID "0000011111111111111111111111111111111111111111111111111111100000"

#define MAX_ECALL_RETURN_LENGTH 10000 // 10 KB is max message length across network

#endif /* _TEECHAIN_H_ */