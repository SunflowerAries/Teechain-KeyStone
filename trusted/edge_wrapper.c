#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "edge_wrapper.h"
#include "edge_defines.h"

void edge_init() {
    /* Nothing for now, will probably register buffers/callsites
        later */
}

void ocall_print_value(unsigned long val) {

    unsigned long val_ = val;
    ocall(OCALL_PRINT_VALUE, &val_, sizeof(unsigned long), 0, 0);

    return;
}

void ocall_send_report(char* buffer, size_t len) {

    ocall(OCALL_SEND_REPORT, buffer, len, 0, 0);

    return;
}

unsigned long ocall_print_buffer(char* data) {

    unsigned long retval;
    ocall(OCALL_PRINT_BUFFER, data, strlen(data)+1, &retval ,sizeof(unsigned long));

    return retval;
}

void ocall_wait_for_message(struct edge_data* msg) {
    ocall(OCALL_WAIT_FOR_MESSAGE, NULL, 0, msg, sizeof(struct edge_data));
}

void ocall_wait_for_client_pubkey(unsigned char* pk, size_t len) {
    ocall(OCALL_WAIT_FOR_CLIENT_PUBKEY, NULL, 0, pk, len);
    return;
}

void ocall_send_reply(unsigned char* data, size_t len) {
    ocall(OCALL_SEND_REPLY, data, len, 0, 0);
    return;
}

void ocall_create_channel(ocall_create_channel_msg_t* msg, size_t len) {
    ocall(OCALL_CREATE_CHANNEL, msg, len, 0, 0);
    return;
}

void ocall_receive_remote_report(void* buffer, size_t len, unsigned char* pk, size_t pk_len) {
    ocall(OCALL_RECEIVE_REMOTE_REPORT, buffer, len, pk, pk_len);
    return;
}

void ocall_receive_remote_report_ack(void* buffer, size_t len, unsigned char* pk, size_t pk_len) {
    ocall(OCALL_RECEIVE_REMOTE_REPORT_ACK, buffer, len, pk, pk_len);
}

void ocall_create_channel_connected(unsigned char* data, size_t len) {
    ocall(OCALL_CREATE_CHANNEL_ACK, data, len, 0, 0);
}