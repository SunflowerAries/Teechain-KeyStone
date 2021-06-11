#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_wrapper.h"

#include "sodium.h"
#include "debug.h"
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
    
    attest_enclave((void*) report_buffer, pk, crypto_kx_PUBLICKEYBYTES);
    ocall_send_report((char*)report_buffer, 2048);
}

void send_reply(int val) {

    ocall_send_reply((unsigned char*)&val, sizeof(int));
}

static void execute_command(char *cmd_msg, int remote_sockfd, int size) {

    if (cmd_msg[0] == OP_PRIMARY) {
        send_reply(ecall_primary((assignment_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_TEECHAIN_SETUP_DEPOSITS) {
        send_reply(ecall_setup_deposits((setup_deposits_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_TEECHAIN_DEPOSITS_MADE) {
        send_reply(ecall_deposits_made((deposits_made_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_CREATE_CHANNEL) {
        send_reply(ecall_create_channel((create_channel_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_VERIFY_DEPOSITS) {
        send_reply(ecall_verify_deposits((generic_channel_msg_t*)(cmd_msg)));
        
    } else if (cmd_msg[0] == OP_REMOTE_CHANNEL_CONNECTED) {
        ecall_remote_channel_connected((generic_channel_msg_t*)(cmd_msg), remote_sockfd);

    } else if (cmd_msg[0] == OP_REMOTE_CHANNEL_CONNECTED_ACK) {
        ecall_remote_channel_connected_ack((generic_channel_msg_t*)(cmd_msg));
    
    } else if (cmd_msg[0] == OP_BALANCE) {
        send_reply(ecall_balance((generic_channel_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_TEECHAIN_DEPOSIT_ADD) {
        send_reply(ecall_add_deposit_to_channel((deposit_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_TEECHAIN_DEPOSIT_REMOVE) {
        send_reply(ecall_remove_deposit_from_channel((deposit_msg_t*)(cmd_msg)));

    } else if (cmd_msg[0] == OP_SEND) {
        ecall_send((send_msg_t*)(cmd_msg));

    } else if (cmd_msg[0] == OP_PROFILE) {
        send_reply(ecall_profile());

    } else if (cmd_msg[0] == OP_ROUND_TRIP) {
        send_reply(ecall_round_trip((send_msg_t*)(cmd_msg)));

    } else {
        // Encrypted message from remote 
        size_t wordmsg_len;
        
        cstring* channel_id = cstr_new_buf(((generic_channel_msg_t*)(cmd_msg))->channel_id, CHANNEL_ID_LEN);
        channel_state_t* state = get_channel_state(channel_id->str);
        unsigned char* ct_msg = (unsigned char*)((generic_channel_msg_t*)(cmd_msg))->blob;
        unsigned long start = getcycles();
        if (remote_channel_recv(state, ct_msg, size - sizeof(generic_channel_msg_t), &wordmsg_len) != 0) {
            free(cmd_msg);
            return;
        }
        unsigned long end = getcycles();
        PRINTF("total cycles to decrypt %d bytes: %lu.\n", size - sizeof(generic_channel_msg_t), end - start);

        if (cmd_msg[0] == OP_REMOTE_CHANNEL_CREATE_DATA) {
            process_channel_create_data(state, (channel_init_msg_t*)ct_msg);
        } else if (cmd_msg[0] == OP_REMOTE_VERIFY_DEPOSITS_ACK) {
            process_verify_deposits_ack(state);
        } else if (cmd_msg[0] == OP_REMOTE_TEECHAIN_DEPOSIT_ADD) {
            process_deposit_add(state, (remote_deposit_msg_t*)ct_msg);
        } else if (cmd_msg[0] == OP_REMOTE_TEECHAIN_DEPOSIT_ADD_ACK) {
            process_deposit_add_ack(state, (secure_ack_msg_t*)ct_msg);
        } else if (cmd_msg[0] == OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE) {
            process_deposit_remove(state, (remote_deposit_msg_t*)ct_msg);
        } else if (cmd_msg[0] == OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE_ACK) {
            process_deposit_remove_ack(state, (secure_ack_msg_t*)ct_msg);
        } else if (cmd_msg[0] == OP_REMOTE_SEND) {
            process_send(state, (remote_send_msg_t*)ct_msg);
        } else if (cmd_msg[0] == OP_REMOTE_SEND_ACK) {
            process_send_ack(state);
        } else if (cmd_msg[0] == OP_ROUND_TRIP0) {
            process_round_trip0(state);
        } else if (cmd_msg[0] == OP_ROUND_TRIP1) {
            process_round_trip1(state);
        }
    }
}

void handle_messages() {
    struct edge_data msg;
    
    while (1) {
        ocall_wait_for_message(&msg);
        if (msg.size == sizeof(int)) {
            continue;
        }
        char* cmd_msg = (char*)malloc(msg.size);

        if (cmd_msg == NULL) {
            ocall_print_buffer("Message too large to store, ignoring\n");
            continue;
        }

        copy_from_shared(cmd_msg, msg.offset, msg.size);
        int sockfd = ((encl_message_t*)cmd_msg)->sockfd;

        char* payload = ((encl_message_t*)cmd_msg)->payload;

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
