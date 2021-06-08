#include "encl_message.h"
#include "edge_wrapper.h"
#include "enclave_expected_hash.h"
#include "sm_expected_hash.h"
#include "channel.h"

#include "edge_defines.h"
// verifier
#include "test_dev_key.h"
#include <string.h>

#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int edge_init(Keystone::Enclave* enclave){

  enclave->registerOcallDispatch(incoming_call_dispatch);
  register_call(OCALL_PRINT_BUFFER, print_buffer_wrapper);
  register_call(OCALL_SEND_REPORT, send_report_wrapper);
  register_call(OCALL_WAIT_FOR_MESSAGE, wait_for_message_wrapper);
  register_call(OCALL_SEND_REPLY, send_reply_wrapper);
  register_call(OCALL_CREATE_CHANNEL, create_channel_wrapper);
  register_call(OCALL_RECEIVE_REMOTE_REPORT, receive_remote_report_wrapper);
  register_call(OCALL_RECEIVE_REMOTE_REPORT_ACK, receive_remote_report_ack_wrapper);
  register_call(OCALL_CREATE_CHANNEL_ACK, create_channel_connected_wrapper);
  register_call(OCALL_SEND_ON_CHANNEL, send_on_channel_wrapper);

  edge_call_init_internals((uintptr_t)enclave->getSharedBuffer(),
			   enclave->getSharedBufferSize());
}

void send_on_channel_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    struct generic_channel_msg_t* msg = (struct generic_channel_msg_t*)call_args;

    channel_state_t* channel_state = get_channel_state(std::string(msg->channel_id, CHANNEL_ID_LEN));

    send_message(msg->msg_op, msg->channel_id, msg->blob, args_len - sizeof(generic_channel_msg_t), channel_state->connection.remote_sockfd);
    edge_call->return_data.call_status = CALL_STATUS_OK;

    return;
}

void create_channel_connected_wrapper(void* buffer) {
    /* For now we assume the call struct is at the front of the shared
    * buffer. This will have to change to allow nested calls. */
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    struct ocall_channel_msg_t* msg = (struct ocall_channel_msg_t*)call_args;
    channel_state_t* channel_state = get_channel_state(std::string(msg->channel_id, CHANNEL_ID_LEN));

    channel_state->connection.remote_sockfd = msg->sockfd;

    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    getpeername(msg->sockfd, (struct sockaddr*)&addr, &len);
    char ipstr[INET6_ADDRSTRLEN];
    int remoteport;

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        remoteport = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        remoteport = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
    }
    channel_state->connection.remote_port = remoteport;
    channel_state->connection.remote_host_len = strlen(ipstr);
    memcpy((char*)channel_state->connection.remote_host, ipstr, channel_state->connection.remote_host_len);

    send_message(OP_REMOTE_CHANNEL_CONNECTED_ACK, msg->channel_id, msg->blob, REPORT_LEN, msg->sockfd);
    edge_call->return_data.call_status = CALL_STATUS_OK;

    return;
}

void receive_remote_report_ack_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    struct generic_channel_msg_t* msg = (struct generic_channel_msg_t*)call_args;

    Report report;
    report.fromBytes((unsigned char*)msg->blob);
#if DEBUG_MODE
    report.printPretty();
#endif
    if (!report.verify(enclave_expected_hash, sm_expected_hash, _sanctum_dev_public_key)) {
        printf("[UT] Attestation signature and enclave hash are invalid\n");
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
    }
    if (report.getDataSize() !=  crypto_kx_PUBLICKEYBYTES) {
        printf("[UT] Bad report data sec size\n");
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
    }

    unsigned char remote_pk[crypto_kx_PUBLICKEYBYTES];
    memcpy((void*)remote_pk, report.getDataSection(), crypto_kx_PUBLICKEYBYTES);

    uintptr_t data_section = edge_call_data_ptr();
    memcpy((void*)data_section, remote_pk, crypto_kx_PUBLICKEYBYTES);

    if (edge_call_setup_ret(edge_call, (void*) data_section, crypto_kx_PUBLICKEYBYTES)) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return;
}

void receive_remote_report_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    struct generic_channel_msg_t* msg = (struct generic_channel_msg_t*)call_args;

    Report report;
    report.fromBytes((unsigned char*)msg->blob);
#if DEBUG_MODE
    report.printPretty();
#endif
    if (!report.verify(enclave_expected_hash, sm_expected_hash, _sanctum_dev_public_key)) {
        printf("[UT] Attestation signature and enclave hash are invalid\n");
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
    }
    if (report.getDataSize() !=  crypto_kx_PUBLICKEYBYTES) {
        printf("[UT] Bad report data sec size\n");
        edge_call->return_data.call_status = CALL_STATUS_ERROR;
        return;
    }

    // printf("receive_remote_report_wrapper.\n");

    unsigned char remote_pk[crypto_kx_PUBLICKEYBYTES];
    memcpy((void*)remote_pk, report.getDataSection(), crypto_kx_PUBLICKEYBYTES);

    std::string temp_channel_id(TEMPORARY_CHANNEL_ID, CHANNEL_ID_LEN);
    channel_state_t* channel_state = get_channel_state(temp_channel_id);
    remove_association(temp_channel_id);
    associate_channel_state(std::string(msg->channel_id, CHANNEL_ID_LEN), channel_state);

    uintptr_t data_section = edge_call_data_ptr();
    memcpy((void*)data_section, remote_pk, crypto_kx_PUBLICKEYBYTES);

    if (edge_call_setup_ret(edge_call, (void*) data_section, crypto_kx_PUBLICKEYBYTES)) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return;
}

void create_channel_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    struct ocall_create_channel_msg_t* msg = (struct ocall_create_channel_msg_t*)call_args;

    channel_state_t* channel_state = create_channel_state();
    channel_state->is_initiator = msg->is_initiator;
    associate_channel_state(std::string(msg->channel_id, CHANNEL_ID_LEN), channel_state);

    if (msg->is_initiator) {
        channel_state->connection.remote_port = msg->remote_port;
        channel_state->connection.remote_host_len = msg->remote_host_len;
        memcpy((char*) channel_state->connection.remote_host, msg->remote_host, channel_state->connection.remote_host_len);
    }

    channel_state->connection.local_sockfd = fd_sock;

    if (msg->is_initiator) {
        channel_state->connection.remote_sockfd = connect_to_socket(std::string(channel_state->connection.remote_host, channel_state->connection.remote_host_len), channel_state->connection.remote_port);
        send_message(OP_REMOTE_CHANNEL_CONNECTED, msg->channel_id, msg->report_buffer, REPORT_LEN, channel_state->connection.remote_sockfd);
        register_new_connection(channel_state->connection.remote_sockfd);
    }

    edge_call->return_data.call_status = CALL_STATUS_OK;
    return;
}

void print_buffer_wrapper(void* buffer) {
    /* For now we assume the call struct is at the front of the shared
    * buffer. This will have to change to allow nested calls. */
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }
    ret_val = print_buffer((char*)call_args);

    // We are done with the data section for args, use as return region
    // TODO safety check?
    uintptr_t data_section = edge_call_data_ptr();

    memcpy((void*)data_section, &ret_val, sizeof(unsigned long));

    if (edge_call_setup_ret(edge_call, (void*) data_section, sizeof(unsigned long))) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return;
}

void send_report_wrapper(void* buffer) {

    /* For now we assume the call struct is at the front of the shared
    * buffer. This will have to change to allow nested calls. */
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t data_section;
    unsigned long ret_val;
    //TODO check the other side of this
    if(edge_call_get_ptr_from_offset(edge_call->call_arg_offset, sizeof(report_t),
                    &data_section) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    send_report((void*)data_section, sizeof(report_t));

    edge_call->return_data.call_status = CALL_STATUS_OK;

    return;
}

void wait_for_message_wrapper(void* buffer) {

    /* For now we assume the call struct is at the front of the shared
    * buffer. This will have to change to allow nested calls. */
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    size_t len;
    encl_message_t* host_msg = wait_for_message(&len);

    // This handles wrapping the data into an edge_data_t and storing it
    // in the shared region.
    if (edge_call_setup_wrapped_ret(edge_call, (void*)host_msg, len)) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return;
}

void send_reply_wrapper(void* buffer) {
    /* For now we assume the call struct is at the front of the shared
    * buffer. This will have to change to allow nested calls. */
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    send_reply((void*)call_args, edge_call->call_arg_size);
    edge_call->return_data.call_status = CALL_STATUS_OK;

    return;
}