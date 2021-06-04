#include "eapp_utils.h"
#include "string.h"
#include "malloc.h"
#include "edge_wrapper.h"

#include "channel.h"

unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];

map_channel_state_t channel_states;

void channel_init() {

    /* libsodium config */
    randombytes_set_implementation(&randombytes_salsa20_implementation);

    if (sodium_init() < 0) {
        ocall_print_buffer("[C] Sodium init failed, exiting\n");
        EAPP_RETURN(1);
    }

    /* Generate our keys */
    if (crypto_kx_keypair(server_pk, server_sk) != 0) {
        ocall_print_buffer("[C] Unable to generate keypair, exiting\n");
        EAPP_RETURN(1);
    }

    /* Init channelstate mapper */
    map_init(&channel_states);
}

void remote_channel_establish(channel_state_t* state, unsigned char* pk) {
    
    /* Ask libsodium to generate session keys based on the recv'd pk */
    if (state->is_initiator != 0) {
        if(crypto_kx_server_session_keys(state->rx, state->tx, server_pk, server_sk, pk) != 0) {
            ocall_print_buffer("[C] Unable to generate session keys, exiting\n");
            EAPP_RETURN(1);
        }
    } else {
        if(crypto_kx_client_session_keys(state->rx, state->tx, server_pk, server_sk, pk) != 0) {
            ocall_print_buffer("[C] Unable to generate session keys, exiting\n");
            EAPP_RETURN(1);
        }
    }
    ocall_print_buffer("[C] Successfully generated session keys.\n");
}

void channel_establish() {

    /* Ask libsodium to generate session keys based on the recv'd pk */

    if(crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk) != 0) {
        ocall_print_buffer("[C] Unable to generate session keys, exiting\n");
        EAPP_RETURN(1);
    }
    ocall_print_buffer("[C] Successfully generated session keys.\n");
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len+(MSG_BLOCKSIZE - (len%MSG_BLOCKSIZE)))

int remote_channel_recv(channel_state_t* state, unsigned char* msg_buffer, size_t len, size_t* datalen) {
    /* We store the nonce at the end of the ciphertext buffer for easy
        access */
    size_t clen = len - crypto_secretbox_NONCEBYTES;
    unsigned char* nonceptr = &(msg_buffer[clen]);

    if (crypto_secretbox_open_easy(msg_buffer, msg_buffer, clen, nonceptr, state->rx) != 0) {
        ocall_print_buffer("[C] Invalid message, ignoring\n");
        return -1;
    }
    size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

    size_t unpad_len;
    if (sodium_unpad(&unpad_len, msg_buffer, ptlen, MSG_BLOCKSIZE) != 0) {
        ocall_print_buffer("[C] Invalid message padding, ignoring\n");
        return -1;
    }

    *datalen = unpad_len;

    return 0;
}

int channel_recv(unsigned char* msg_buffer, size_t len, size_t* datalen) {
    /* We store the nonce at the end of the ciphertext buffer for easy
        access */
    size_t clen = len - crypto_secretbox_NONCEBYTES;
    unsigned char* nonceptr = &(msg_buffer[clen]);

    if (crypto_secretbox_open_easy(msg_buffer, msg_buffer, clen, nonceptr, rx) != 0) {
        ocall_print_buffer("[C] Invalid message, ignoring\n");
        return -1;
    }
    size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

    size_t unpad_len;
    if (sodium_unpad(&unpad_len, msg_buffer, ptlen, MSG_BLOCKSIZE) != 0) {
        ocall_print_buffer("[C] Invalid message padding, ignoring\n");
        return -1;
    }

    *datalen = unpad_len;

    return 0;
}

size_t channel_get_send_size(size_t len) {
    return crypto_secretbox_MACBYTES + BLOCK_UP(len) + crypto_secretbox_NONCEBYTES;
}

unsigned char* remote_channel_box(channel_state_t* state, unsigned char* msg, size_t size, size_t* finalsize) {
    /* We store the nonce at the end of the ciphertext buffer for easy
        access */

    size_t size_padded = BLOCK_UP(size);
    *finalsize = size_padded + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
    unsigned char* buffer = (unsigned char*)malloc(*finalsize);

    if (buffer == NULL) {
        ocall_print_buffer("[C] Too large to allocate\n");
        EAPP_RETURN(1);
    }

    memcpy(buffer, msg, size);

    size_t buf_padded_len;
    if (sodium_pad(&buf_padded_len, buffer, size, MSG_BLOCKSIZE, size_padded) != 0) {
        ocall_print_buffer("[C] Unable to pad message, exiting\n");
        EAPP_RETURN(1);
    }

    unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES+buf_padded_len]);
    randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, state->tx) != 0) {
        ocall_print_buffer("[C] Unable to encrypt message, exiting\n");
        EAPP_RETURN(1);
    }

    return buffer;
}

void channel_box(unsigned char* msg, size_t len, unsigned char* buffer) {
    /* We store the nonce at the end of the ciphertext buffer for easy
        access */

    size_t buf_padded_len;

    memcpy(buffer, msg, len);

    if (sodium_pad(&buf_padded_len, buffer, len, MSG_BLOCKSIZE, BLOCK_UP(len)) != 0) {
        ocall_print_buffer("[C] Unable to pad message, exiting\n");
        EAPP_RETURN(1);
    }

    unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES+buf_padded_len]);
    randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, tx) != 0) {
        ocall_print_buffer("[C] Unable to encrypt message, exiting\n");
        EAPP_RETURN(1);
    }

}

static void init_channel_state(channel_state_t* state) {
    state->status = Unverified;

    state->remote_last_seen = 0;
    state->my_monotonic_counter = 0;
    state->my_sends = 0;
    state->my_receives = 0;

    state->deposits_verified = 0;
}

channel_state_t* create_channel_state() {
    channel_state_t *state = (channel_state_t*)malloc(sizeof(channel_state_t));
    init_channel_state(state);
    return state;
}

void remove_association(char* channel_id) {
    map_remove(&channel_states, channel_id);
}

void associate_channel_state(char* channel_id, channel_state_t* state_to_associate) {
    memcpy(state_to_associate->channel_id, channel_id, CHANNEL_ID_LEN);
    map_set(&channel_states, channel_id, *state_to_associate);
}

channel_state_t* get_channel_state(char* channel_id) {
    return (channel_state_t*)map_get(&channel_states, channel_id);
}

int check_status(channel_state_t* state, enum channel_status_t status) {
    if (state->status != status) {
        return -1;
    }
    return 0;
}