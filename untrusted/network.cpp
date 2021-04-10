#include <string.h>

#include "teechain.h"
#include "network.h"

#include "test_dev_key.h"
#include "enclave_expected_hash.h"
#include "sm_expected_hash.h"

unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];

int double_fault;
int channel_ready;

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

void untrusted_teechain_init() {
    if (sodium_init() != 0) {
        printf("[UT] Libsodium init failure\n");
        untrusted_teechain_exit();
    }
    if (crypto_kx_keypair(client_pk, client_sk) != 0) {
        printf("[UT] Libsodium keypair gen failure\n");
        untrusted_teechain_exit();
    }

    channel_ready = 0;
}

byte* untrusted_teechain_pubkey(size_t* len) {
    *len = crypto_kx_PUBLICKEYBYTES;
    return (byte*)client_pk;
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

    if (report.getDataSize() !=  crypto_kx_PUBLICKEYBYTES) {
        printf("[UT] Bad report data sec size\n");
        untrusted_teechain_exit();
    }

    memcpy(server_pk, report.getDataSection(), crypto_kx_PUBLICKEYBYTES);

    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
        printf("[UT] Bad session keygen\n");
        untrusted_teechain_exit();
    }

    printf("[UT] Session keys established\n");
    channel_ready = 1;
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len + (MSG_BLOCKSIZE - (len % MSG_BLOCKSIZE)))

byte* untrusted_teechain_box(byte* msg, size_t size, size_t* finalsize) {
    size_t size_padded = BLOCK_UP(size);
    *finalsize = size_padded + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
    byte* buffer = (byte*)malloc(*finalsize);
    if (buffer == NULL) {
        printf("[UT] NOMEM for msg\n");
        untrusted_teechain_exit();
    }

    memcpy(buffer, msg, size);

    size_t buf_padded_len;
    if (sodium_pad(&buf_padded_len, buffer, size, MSG_BLOCKSIZE, size_padded) != 0) {
        printf("[UT] Unable to pad message, exiting\n");
        untrusted_teechain_exit();
    }

    unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES + buf_padded_len]);
    randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, tx) != 0) {
        printf("[UT] secretbox failed\n");
        untrusted_teechain_exit();
    }

    return(buffer);
}

void untrusted_teechain_unbox(unsigned char* buffer, size_t len) {

    size_t clen = len - crypto_secretbox_NONCEBYTES;
    unsigned char* nonceptr = &(buffer[clen]);
    if (crypto_secretbox_open_easy(buffer, buffer, clen, nonceptr, rx) != 0) {
        printf("[UT] unbox failed\n");
        untrusted_teechain_exit();
    }

    size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
    size_t unpad_len;
    if (sodium_unpad(&unpad_len, buffer, ptlen, MSG_BLOCKSIZE) != 0) {
        printf("[UT] Invalid message padding, ignoring\n");
        untrusted_teechain_exit();
    }


    return;
}

int untrusted_teechain_read_reply(unsigned char* data, size_t len) {

    untrusted_teechain_unbox(data, len);
    printf("%s\n", data);

}

void send_exit_message() {
    size_t pt_size;
    CommandMsg* pt_msg = generate_exit_message(&pt_size);

    size_t ct_size;
    byte* ct_msg = untrusted_teechain_box((byte*)pt_msg, pt_size, &ct_size);

    send_buffer(ct_msg, ct_size);

    free(pt_msg);
    free(ct_msg);
}

void send_cmd_message(char* msg) {
    size_t pt_size;
    CommandMsg* pt_msg = generate_cmd_message(msg, strlen(msg)+1, &pt_size);

    size_t ct_size;
    byte* ct_msg = untrusted_teechain_box((byte*)pt_msg, pt_size, &ct_size);
    
    send_buffer(ct_msg, ct_size);

    free(pt_msg);
    free(ct_msg);
}

CommandMsg* generate_cmd_message(char* msg, size_t msg_len, size_t* finalsize) {
    CommandMsg* message_buffer = (CommandMsg*)malloc(msg_len+sizeof(CommandMsg));

    message_buffer->msg_op = OP_CMD;
    message_buffer->len = msg_len;
    memcpy(message_buffer->msg, msg, msg_len);

    *finalsize = msg_len + sizeof(CommandMsg);

    return message_buffer;
};

CommandMsg* generate_exit_message(size_t* finalsize) {
    CommandMsg* message_buffer = (CommandMsg*)malloc(sizeof(CommandMsg));
    message_buffer->msg_op = OP_QUIT;

    *finalsize = sizeof(CommandMsg);

    return message_buffer;
}
