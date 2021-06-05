#ifndef _MESSAGE_H_
#define _MESSAGE_H_

/* Set this to 0 if you do not want to debug with much info */
#ifndef DEBUG_MODE
# define DEBUG_MODE 0
#endif

#define RES_SUCCESS 0
#define RES_WRONG_STATE 1
#define RES_WRONG_LIBBTC 2
#define RES_WRONG_ARGS 3
#define RES_WRONG_CHANNEL_STATE 4

// channel constants
#define CHANNEL_ID_LEN 16
#define REMOTE_HOST_LEN 128
#define REPORT_LEN 2048

// bitcoin constants
#define BITCOIN_ADDRESS_LEN 34
#define BITCOIN_PUBLIC_KEY_LEN 66
#define BITCOIN_PRIVATE_KEY_LEN 52
#define BITCOIN_TX_HASH_LEN 64
#define MAX_BITCOIN_TX_SCRIPT_LEN 256
#define MAX_BITCOIN_TX_LEN 3000

// teechain deposit and chain constants
#define MAX_NUM_SETUP_DEPOSITS 10
#define MAX_NUM_CHANNEL_HOPS 10

#define OP_QUIT 0

// ghost assignment message codes
#define OP_PRIMARY 10 // send primary assignment to ghost enclave
#define OP_BACKUP 11 // send backup assignment to ghost enclave

// primary setup message codes
#define OP_TEECHAIN_SETUP_DEPOSITS 20 // send local setup deposits to primary
#define OP_TEECHAIN_SETUP 21 // send local setup deposits to primary
#define OP_TEECHAIN_SETUP_TXID 22 // send local setup transaction hash to primary
#define OP_TEECHAIN_DEPOSITS_MADE 23 // send local deposits made message to primary

// primary channel create message codes
#define OP_CREATE_CHANNEL 30 // create a channel (local message)
#define OP_REMOTE_CHANNEL_CONNECTED 31  // the initiator generated the channel id (remote message) 
#define OP_REMOTE_CHANNEL_CONNECTED_ACK 32 // the receiver send back ack (remote message)
#define OP_REMOTE_CHANNEL_CREATE_DATA 33 // create a channel (remote message)
#define OP_VERIFY_DEPOSITS 34 // tell local enclave channel established
#define OP_REMOTE_VERIFY_DEPOSITS_ACK 35 // tell remote channel has been established on remote end

typedef struct exit_msg_t {
    char msg_op;
} exit_msg_t;

typedef struct assignment_msg_t {
    // operation
    char msg_op;
    char use_monotonic_counters;
} assignment_msg_t;

typedef struct setup_deposits_msg_t {
    char msg_op;
    unsigned long long num_deposits;
} setup_deposits_msg_t;

typedef struct deposit_made_msg_t {
    char txid[BITCOIN_TX_HASH_LEN];
    unsigned long long tx_idx;
    unsigned long long deposit_amount;
} deposit_made_msg_t;

typedef struct deposits_made_msg_t {
    char msg_op;
    char my_address[BITCOIN_ADDRESS_LEN];
    unsigned long long miner_fee;
    unsigned long long num_deposits;
    struct deposit_made_msg_t deposits[MAX_NUM_SETUP_DEPOSITS];
} deposits_made_msg_t;

typedef struct create_channel_msg_t {
    char msg_op;
    char channel_id[CHANNEL_ID_LEN];
    char initiator;
    unsigned long long remote_host_len;
    char remote_host[REMOTE_HOST_LEN];
    unsigned long remote_port;
} create_channel_msg_t;

typedef struct ocall_create_channel_msg_t {
    char channel_id[CHANNEL_ID_LEN];
    char is_initiator;
    unsigned long long remote_host_len;
    char remote_host[REMOTE_HOST_LEN];
    unsigned long remote_port;
    unsigned char report_buffer[REPORT_LEN];
} ocall_create_channel_msg_t;

typedef struct generic_channel_msg_t {
    char msg_op;
    char channel_id[CHANNEL_ID_LEN];
    char blob[];
} generic_channel_msg_t;

typedef struct remote_deposit_made_msg_t {
    char txid[BITCOIN_TX_HASH_LEN];
    unsigned long long tx_idx;
    unsigned long long deposit_amount;

    char deposit_bitcoin_address[BITCOIN_ADDRESS_LEN];
    char deposit_public_keys[BITCOIN_PUBLIC_KEY_LEN];
    char deposit_private_keys[BITCOIN_PRIVATE_KEY_LEN];
} remote_deposit_made_msg_t;

typedef struct channel_init_msg_t {
    char channel_id[CHANNEL_ID_LEN];
    char bitcoin_address[BITCOIN_ADDRESS_LEN];
    unsigned long long num_deposits;
    struct remote_deposit_made_msg_t deposits[MAX_NUM_SETUP_DEPOSITS];
} channel_init_msg_t;

typedef struct ocall_channel_msg_t {
    int sockfd;
    char channel_id[CHANNEL_ID_LEN];
    char blob[];
} ocall_channel_msg_t;

typedef struct encl_message_t {
    int sockfd;
    char payload[];
} encl_message_t;

#endif /* _MESSAGE_H_ */