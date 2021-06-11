#include <string.h>
#include <unistd.h>

#include "teechain.h"
#include "network.h"

#include "test_dev_key.h"
#include "enclave_expected_hash.h"
#include "sm_expected_hash.h"

int double_fault;
int channel_ready;

byte send_ack_buffer[72];

void untrusted_teechain_exit() {
    if (double_fault || !channel_ready) {
        printf("DC: Fatal error, exiting. Remote not cleanly shut down.\n");
        exit(-1);
    } else {
        double_fault = 1;
        printf("[UT] Exiting. Attempting clean remote shutdown.\n");
        send_exit_message();
        exit(0);
    }
}

void untrusted_teechain_get_report(void* buffer, int ignore_valid) {
    Report report;
    report.fromBytes((unsigned char*)buffer);
    report.printPretty();

    if (report.verify(enclave_expected_hash, sm_expected_hash, _sanctum_dev_public_key)) {
        printf("[UT] Attestation signature and enclave hash are valid\n");
    } else {
        printf("[UT] Attestation report is NOT valid\n");
        if (ignore_valid) {
            printf("[UT] Ignore Validation was set, CONTINUING WITH INVALID REPORT\n");
        } else {
            untrusted_teechain_exit();
        }
    }

    channel_ready = 1;
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len + (MSG_BLOCKSIZE - (len % MSG_BLOCKSIZE)))

void untrusted_teechain_read_reply(unsigned char* data, size_t len) {

    int* replyval = (int*)data;
    if (*replyval != RES_SUCCESS) {
        printf("[TT] Enclave fails due to %d.\n",*replyval);
    } else {
        if (!in_benchmark) {
            printf("[TT] Enclave finish command successfully.\n");
        }
    }

}

void send_exit_message() {
    
    struct op_msg_t msg;
    msg.msg_op = OP_QUIT;

    send_buffer((byte*)&msg, sizeof(op_msg_t));
}

void wait_for_send_ack() {
    size_t ack_size;
    read(client_sockfd, (byte*)&ack_size, sizeof(size_t));
    size_t n_read = read(client_sockfd, send_ack_buffer, ack_size);
    // printf("n_read: %d, ack_size: %d.\n", n_read, ack_size);
    if (*((int*)send_ack_buffer) == OP_ACK) {
        if (!in_benchmark) {
            printf("Your payment has been sent!\n");
        }
    } else {
        printf("Send error: %d.\n", *((int*)send_ack_buffer));
    }
}