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

#include "cstr.h"

// TODO sizeof report
unsigned char report_buffer[2048];

void attest_and_establish_channel() {
    
    attest_enclave((void*) report_buffer, server_pk, crypto_kx_PUBLICKEYBYTES);
    ocall_send_report((char*)report_buffer, 2048);

    ocall_wait_for_client_pubkey(client_pk, crypto_kx_PUBLICKEYBYTES);
    channel_establish();
}

static void send_reply(int val) {
    size_t reply_size = channel_get_send_size(sizeof(int));
    unsigned char* reply_buffer = (unsigned char*)malloc(reply_size);
    if (reply_buffer == NULL) {
        ocall_print_buffer("Reply too large to allocate, no reply sent\n");
        EAPP_RETURN(1);
    }

    channel_box((unsigned char*)&val, sizeof(int), reply_buffer);
    ocall_send_reply(reply_buffer, reply_size);

    free(reply_buffer);
}

static void execute_command(char *cmd_msg, int remote_sockfd, int size) {

    if (cmd_msg[0] == OP_PRIMARY) {
        send_reply(ecall_primary());

    } else if (cmd_msg[0] == OP_TEECHAIN_SETUP_DEPOSITS) {
        send_reply(ecall_setup_deposits((setup_deposits_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_TEECHAIN_DEPOSITS_MADE) {
        send_reply(ecall_deposits_made((deposits_made_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_CREATE_CHANNEL) {
        send_reply(ecall_create_channel((create_channel_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_VERIFY_DEPOSITS) {
        send_reply(ecall_verify_deposits((generic_channel_msg_t*)(cmd_msg)));
        
    } else if (cmd_msg[0] == OP_REMOTE_CHANNEL_CONNECTED) {
        send_reply(ecall_remote_channel_connected((generic_channel_msg_t*)(cmd_msg), remote_sockfd));

    } else if (cmd_msg[0] == OP_REMOTE_CHANNEL_CONNECTED_ACK) {
        send_reply(ecall_remote_channel_connected_ack((generic_channel_msg_t*)(cmd_msg)));
    } else {
        // Encrypted message from remote 
        size_t wordmsg_len;
        
        cstring* channel_id = cstr_new_buf(((generic_channel_msg_t*)(cmd_msg))->channel_id, CHANNEL_ID_LEN);
        channel_state_t* state = get_channel_state(channel_id->str);
        unsigned char* ct_msg = (unsigned char*)((generic_channel_msg_t*)(cmd_msg))->blob;
        if (remote_channel_recv(state, ct_msg, size - sizeof(generic_channel_msg_t), &wordmsg_len) != 0) {
            free(cmd_msg);
            return;
        }
        if (cmd_msg[0] == OP_REMOTE_CHANNEL_CREATE_DATA) {
            ecall_remote_channel_init_ack(state, (channel_init_msg_t*)ct_msg);
        } else if(cmd_msg[0] == OP_REMOTE_VERIFY_DEPOSITS_ACK) {
            ecall_remote_verify_deposits_ack(state);
        }
    }
}

void handle_messages() {
    struct edge_data msg;
    static int local_sockfd = -1;
    
    while (1) {
        ocall_wait_for_message(&msg);
        if (msg.size == sizeof(int)) {
            continue;
        }
        char* cmd_msg = (char*)malloc(msg.size);
        size_t wordmsg_len;

        if (cmd_msg == NULL) {
            ocall_print_buffer("Message too large to store, ignoring\n");
            continue;
        }

        copy_from_shared(cmd_msg, msg.offset, msg.size);
        int sockfd = ((encl_message_t*)cmd_msg)->sockfd;
        if (local_sockfd == -1) {
            local_sockfd = sockfd;
        }
        char* payload = ((encl_message_t*)cmd_msg)->payload;
        if (local_sockfd == sockfd) {
            // Message from local agent
            if (channel_recv((unsigned char*)payload, msg.size - sizeof(int), &wordmsg_len) != 0) {
                free(cmd_msg);
                continue;
            }
        }

        if (payload[0] == OP_QUIT) {
            ocall_print_buffer("Received exit, exiting\n");
            EAPP_RETURN(0);
        }

        execute_command(payload, sockfd, msg.size - sizeof(int));

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

    handle_messages();

    EAPP_RETURN(0);
}
