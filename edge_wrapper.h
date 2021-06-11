#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_

#include <edge_call.h>
#include "keystone.h"

#define crypto_kx_PUBLICKEYBYTES 32


typedef struct encl_message_t {
    int sockfd;
    char payload[];
} encl_message_t;

int edge_init(Keystone::Enclave* enclave);

void print_buffer_wrapper(void* buffer);
unsigned long print_buffer(char* str);

void print_value_wrapper(void* buffer);
void print_value(unsigned long val);

void send_report_wrapper(void* buffer);
void send_report(void* shared_buffer, size_t len);

void wait_for_message_wrapper(void* buffer);
encl_message_t* wait_for_message(size_t* len);

void send_reply_wrapper(void* buffer);
void send_reply(void* message, size_t len);

void register_new_connection(int conn_sock);

void create_channel_connected_wrapper(void* buffer);

void receive_remote_report_ack_wrapper(void* buffer);

void receive_remote_report_wrapper(void* buffer);

void create_channel_wrapper(void* buffer);

void send_on_channel_wrapper(void* buffer);

void profile_wrapper(void* buffer);

#endif /* _EDGE_WRAPPER_H_ */
