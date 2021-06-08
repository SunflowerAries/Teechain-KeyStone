#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include "message.h"
#include "state.h"
#include "map.h"
#include "sodium.h"

enum channel_status_t {
    Unverified,  // not yet verified by the remote
    Alive,  // alive and ready to rock
    Settled,  // has been settled
};

typedef struct channel_state_t {
    enum channel_status_t status;
    char channel_id[CHANNEL_ID_LEN];
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];
    char is_initiator;

    char deposits_verified;
    char other_party_deposits_verified;
    
    struct setup_transaction_t remote_setup_transaction;

    char most_recent_nonce[NONCE_BYTE_LEN];

    // account totals and monotonic counters
    unsigned long long my_balance;
    unsigned long long remote_balance;
    unsigned long long remote_last_seen;      // highest seen transaction from the remote side
    unsigned long long my_monotonic_counter;  // the id of the last transaction sent from me to the other side

    // transactions processed, just for debugging and information
    int my_sends;
    int my_receives;
} channel_state_t;

typedef map_t(channel_state_t) map_channel_state_t;

void channel_init();
void remote_channel_establish(channel_state_t* state, unsigned char* remote_pk);
int remote_channel_recv(channel_state_t* state, unsigned char* msg_buffer, size_t len, size_t* datalen);
unsigned char* remote_channel_box(channel_state_t* state, unsigned char* msg, size_t size, size_t* finalsize);
extern unsigned char report_buffer[];
extern unsigned char pk[], sk[];
extern unsigned char rx[];
extern unsigned char tx[];

channel_state_t* create_channel_state();
void remove_association(char* channel_id);
void associate_channel_state(char* channel_id, channel_state_t* state_to_associate);
channel_state_t* get_channel_state(char* channel_id);
int check_status(channel_state_t* state, enum channel_status_t status);

#endif /* _CHANNEL_H_ */
