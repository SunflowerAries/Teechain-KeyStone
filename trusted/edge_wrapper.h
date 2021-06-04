#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_
#include "edge_call.h"
#include "message.h"
void edge_init();

unsigned long ocall_print_buffer(char* data);
void ocall_print_value(unsigned long val);
void ocall_wait_for_message(struct edge_data *msg);
void ocall_wait_for_client_pubkey(unsigned char* pk, size_t len);
void ocall_send_report(char* buffer, size_t len);
void ocall_send_reply(unsigned char* data, size_t len);
void ocall_create_channel(ocall_create_channel_msg_t* msg, size_t len);
void ocall_receive_remote_report(void* buffer, size_t len, unsigned char* pk, size_t pk_len);
void ocall_receive_remote_report_ack(void* buffer, size_t len, unsigned char* pk, size_t pk_len);
void ocall_create_channel_connected(unsigned char* data, size_t len);
void ocall_send_on_channel(void* data, size_t len);
#endif /* _EDGE_WRAPPER_H_ */
