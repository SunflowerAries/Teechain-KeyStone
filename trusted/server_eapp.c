#include "app/eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_wrapper.h"
#include "sodium.h"
#include "hacks.h"
#include "channel.h"
#include "command.h"
#include "teechain.h"

void attest_and_establish_channel(){
    // TODO sizeof report
    char buffer[2048];
    attest_enclave((void*) buffer, server_pk, crypto_kx_PUBLICKEYBYTES);
    ocall_send_report(buffer, 2048);

    ocall_wait_for_client_pubkey(client_pk, crypto_kx_PUBLICKEYBYTES);
    channel_establish();
}

void handle_messages() {
    struct edge_data msg;
    while (1) {
        ocall_wait_for_message(&msg);
        CommandMsg* cmd_msg = malloc(msg.size);
        size_t wordmsg_len;

        if (cmd_msg == NULL) {
            ocall_print_buffer("Message too large to store, ignoring\n");
            continue;
        }

        copy_from_shared(cmd_msg, msg.offset, msg.size);
        if (channel_recv((unsigned char*)cmd_msg, msg.size, &wordmsg_len) != 0) {
            free(cmd_msg);
            continue;
        }

        if (cmd_msg->msg_op == OP_PRIMARY) {
            ecall_primary();
        }

        // Done with the message, free it
        free(cmd_msg);

        // size_t reply_size = channel_get_send_size(sizeof(int));
        // unsigned char* reply_buffer = malloc(reply_size);
        // if(reply_buffer == NULL){
        // ocall_print_buffer("Reply too large to allocate, no reply sent\n");
        // continue;
        // }

        // channel_send((unsigned char*)&val, sizeof(int), reply_buffer);
        // ocall_send_reply(reply_buffer,reply_size);

        // free(reply_buffer);
    }
}

void EAPP_ENTRY eapp_entry() {
    edge_init();
    magic_random_init();
    channel_init();

    attest_and_establish_channel();
    handle_messages();

    EAPP_RETURN(0);
}
