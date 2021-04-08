#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include "command.h"
#include "sodium.h"
#include "report.h"

typedef unsigned char byte;

#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 8067

void send_buffer(byte* buffer, size_t len);
byte* recv_buffer(size_t* len);

void trusted_client_exit();
void trusted_client_init();
byte* trusted_client_pubkey(size_t* len);
void trusted_client_get_report(void* buffer, int ignore_valid);
int trusted_client_read_reply(unsigned char* data, size_t len);
void send_exit_message();
void send_message(char* msg, size_t msg_len);

byte* trusted_client_box(byte* msg, size_t size, size_t* finalsize);
void trusted_client_unbox(unsigned char* buffer, size_t len);

#endif /* _NETWORK_H_ */