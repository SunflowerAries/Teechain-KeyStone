#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_wrapper.h"

#include "sodium.h"
#include "hacks.h"
#include "syscall_wrapper.h"

#include "channel.h"
#include "message.h"
#include "teechain.h"
#include "utils.h"

void attest_and_establish_channel(){
    // TODO sizeof report
    char buffer[2048];
    attest_enclave((void*) buffer, server_pk, crypto_kx_PUBLICKEYBYTES);
    ocall_send_report(buffer, 2048);

    ocall_wait_for_client_pubkey(client_pk, crypto_kx_PUBLICKEYBYTES);
    channel_establish();
}

static void send_reply(int val) {
    size_t reply_size = channel_get_send_size(sizeof(int));
    unsigned char* reply_buffer = (unsigned char*)malloc(reply_size);
    if (reply_buffer == NULL) {
        ocall_print_buffer("Reply too large to allocate, no reply sent\n");
        // continue;
    }

    channel_send((unsigned char*)&val, sizeof(int), reply_buffer);
    ocall_send_reply(reply_buffer, reply_size);

    free(reply_buffer);
}

static void execute_command(char *cmd_msg) {

    if (cmd_msg[0] == OP_PRIMARY) {
        send_reply(ecall_primary());

    } else if (cmd_msg[0] == OP_TEECHAIN_SETUP_DEPOSITS) {
        struct setup_deposits_msg_t data = *((setup_deposits_msg_t*) (cmd_msg));
        send_reply(ecall_setup_deposits(data));
    }
}

void handle_messages() {
    struct edge_data msg;
    
    while (1) {
        ocall_wait_for_message(&msg);
        char* cmd_msg = (char*)malloc(msg.size);
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

        if (cmd_msg[0] == OP_QUIT) {
            ocall_print_buffer("Received exit, exiting\n");
            EAPP_RETURN(0);
        }

        execute_command(cmd_msg);

        // Done with the message, free it
        free(cmd_msg);

    }
}

void EAPP_ENTRY eapp_entry() {
    edge_init();
    magic_random_init();
    channel_init();

    attest_and_establish_channel();
    teechain_init();
    ocall_print_buffer("After teechain_init.\n");

    handle_messages();

    EAPP_RETURN(0);
}
