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

#define DEFAULT_PORT 8067

void untrusted_teechain_exit();
void untrusted_teechain_init();
byte* untrusted_teechain_pubkey(size_t* len);
void untrusted_teechain_get_report(void* buffer, int ignore_valid);
int untrusted_teechain_read_reply(unsigned char* data, size_t len);
void send_exit_message();
void send_cmd_message(char* msg, int opt);
CommandMsg* generate_exit_message(size_t* finalsize);
CommandMsg* generate_cmd_message(char* msg, size_t msg_len, size_t* finalsize);

byte* untrusted_teechain_box(byte* msg, size_t size, size_t* finalsize);
void untrusted_teechain_unbox(unsigned char* buffer, size_t len);

#endif /* _NETWORK_H_ */