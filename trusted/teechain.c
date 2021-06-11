#include "teechain.h"
#include "state.h"
#include "utils.h"
#include "channel.h"
#include "debug.h"

// keystone
#include "edge_wrapper.h"
#include "string.h"

// libsodium
#include "sodium.h"

// libbtc
#include "btc.h"
#include "random.h"
#include "cstr.h"
#include "vector.h"
#include "ecc.h"
#include "ecc_key.h"
#include "script.h"
#include "tool.h"
#include "chainparams.h"

const btc_chainparams *chain = &btc_chainparams_test;

// Global setup transaction for this enclave
setup_transaction_t my_setup_transaction;
int benchmark = false;

unsigned long start0, end0;

void teechain_init() {
    btc_ecc_start();
    map_init(&my_setup_transaction.deposit_ids_to_channels);
    map_init(&my_setup_transaction.deposit_ids_to_deposits);
}

int ecall_primary(assignment_msg_t* msg) {

    if (check_state(Ghost) != 0) {
        ocall_print_buffer("Cannot assign this node as primary; not in the correct state!\n");
        return RES_WRONG_STATE;
    }
    teechain_state = Primary;
    benchmark = msg->benchmark;
    ocall_print_buffer("Your Enclave has been made into a Primary Teechain node!\n"
        "To use it, please fund your enclave by setting up your funding deposits!\n");
    return RES_SUCCESS;
}

int ecall_setup_deposits(setup_deposits_msg_t* msg) {
    
    if (check_state(Primary) != 0) {
        ocall_print_buffer("Cannot setup deposits; this enclave is not a primary!\n");
        return RES_WRONG_STATE;
    }

    ocall_print_buffer("Please generate bitcoin funding transactions that deposit funds into the following Bitcoin addresses.\n"
        "For each of the Bitcoin addresses generated below, you'll have the chance to specify the transaction id, unspent transaction output, and the amount deposited into that address in the next step of the protocol.\n");

    size_t sizeout = 128;
    char privkey_wif[sizeout];
    char pubkey_hex[sizeout];

    char address_p2pkh[sizeout];

    btc_key key;
    // pubkey hash
    btc_pubkey pubkey;
    cstring* p2pkh = cstr_new_sz(1024);

    ocall_print_buffer("Please deposit into bitcoin addresses below:\n");

    // generate and print bitcoin addresses to be paid into by the user
    for (unsigned long long i = 0; i < msg->num_deposits; i++) {
        // create new deposit
        deposit_t deposit;
        deposit.is_spent = 0;
        deposit.deposit_amount = 0;
        // deposit_t* deposit = (deposit_t *)malloc(sizeof(deposit_t));
        // deposit->is_spent = 0;
        // deposit->deposit_amount = 0;
        
        btc_privkey_init(&key);
        btc_privkey_gen(&key);
        btc_privkey_encode_wif(&key, chain, privkey_wif, &sizeout);
        
        btc_pubkey_init(&pubkey);
        btc_pubkey_from_key(&key, &pubkey);
        if (!btc_pubkey_is_valid(&pubkey)) {
            return RES_WRONG_LIBBTC;
        }
        btc_pubkey_get_hex(&pubkey, pubkey_hex, &sizeout);

        btc_script_build_p2pkh(p2pkh, pubkey.pubkey);

        btc_pubkey_getaddr_p2pkh(&pubkey, chain, address_p2pkh);

        memcpy(deposit.bitcoin_address, address_p2pkh, BITCOIN_ADDRESS_LEN);
        memcpy(deposit.public_key, pubkey.pubkey, pubkey.compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);
        memcpy(deposit.private_key, key.privkey, BTC_ECKEY_PKEY_LENGTH);

        btc_privkey_cleanse(&key);
        btc_pubkey_cleanse(&pubkey);

        map_set(&my_setup_transaction.deposit_ids_to_deposits, ulltostr(i), deposit);
        PRINTF("%s\n", address_p2pkh);

        memset(privkey_wif, 0, strlen(privkey_wif));
        memset(pubkey_hex, 0, strlen(pubkey_hex));
        
        memset(address_p2pkh, 0, strlen(address_p2pkh));
    }

    my_setup_transaction.num_deposits = msg->num_deposits;

    teechain_state = WaitingForFunds;

    cstr_free(p2pkh, true);
    return RES_SUCCESS;
}

int ecall_deposits_made(deposits_made_msg_t* msg) {

    if (check_state(WaitingForFunds) != 0) {
        ocall_print_buffer("Cannot make the deposits into the enclave; setup deposits hasn't been called!\n");
        return RES_WRONG_STATE;
    }

    if (my_setup_transaction.num_deposits != msg->num_deposits) {
        ocall_print_buffer("Number of deposits made does not match the number given to ecall_setup_deposits\n");
        return RES_WRONG_ARGS;
    }

    // store enclave state for Setup transaction
    memcpy(my_setup_transaction.my_address, msg->my_address, BITCOIN_ADDRESS_LEN);
    my_setup_transaction.miner_fee = msg->miner_fee;

    // store deposit information for setup transaction and 
    for (unsigned long long i = 0; i < my_setup_transaction.num_deposits; i++) {
        // update deposit amount and script
        deposit_t* deposit = map_get(&my_setup_transaction.deposit_ids_to_deposits, ulltostr(i));
        memcpy(deposit->txid, msg->deposits[i].txid, BITCOIN_TX_HASH_LEN);
        deposit->tx_idx = msg->deposits[i].tx_idx;
        deposit->deposit_amount = msg->deposits[i].deposit_amount;
    }

    teechain_state = Funded;
    PRINTF("Loaded %u funding deposits into the Enclave.\nYou are ready to begin creating channels!\n", my_setup_transaction.num_deposits);
    return RES_SUCCESS;
}

int ecall_create_channel(create_channel_msg_t* msg) {

    if (check_state(Funded) != 0) {
        ocall_print_buffer("Cannot create new channel; this enclave is not funded!\n");
        return RES_WRONG_STATE;
    }

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);

    channel_state_t* state = create_channel_state();
    state->is_initiator = msg->initiator;
    state->my_balance = 0;

    associate_channel_state(channel_id->str, state);

    ocall_create_channel_msg_t ocall_msg;
    memcpy(ocall_msg.channel_id, msg->channel_id, CHANNEL_ID_LEN);
    ocall_msg.is_initiator = msg->initiator;

    if (ocall_msg.is_initiator != 0) {
        ocall_msg.remote_port = msg->remote_port;
        ocall_msg.remote_host_len = msg->remote_host_len;
        memcpy((char*)ocall_msg.remote_host, msg->remote_host, msg->remote_host_len);
        memcpy((char*)ocall_msg.report_buffer, report_buffer, REPORT_LEN);
    }

    ocall_create_channel(&ocall_msg, sizeof(ocall_create_channel_msg_t));
    cstr_free(channel_id, true);
    return RES_SUCCESS;
}

int ecall_verify_deposits(generic_channel_msg_t* msg) {

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    channel_state_t *state = get_channel_state(channel_id->str);

    if (check_status(state, Unverified) != 0) {
        ocall_print_buffer("Cannot verify deposits for channel; channel is not in the correct state!\n");
        return RES_WRONG_CHANNEL_STATE;
    }

    state->deposits_verified = 1;

    if (state->other_party_deposits_verified) {
        state->status = Alive;
    }

    send_on_channel(OP_REMOTE_VERIFY_DEPOSITS_ACK, state, NULL, 0);

    PRINTF("You have verified the funding transaction of the remote party in channel: %s\n", channel_id->str);
    cstr_free(channel_id, true);
    return RES_SUCCESS;
}

int ecall_remote_channel_connected(generic_channel_msg_t* msg, int remote_sockfd) {

    if (check_state(Funded) != 0 && check_state(Backup) != 0) {
        ocall_print_buffer("Cannot set the channel id; this enclave is not in the correct state!\n");
        return RES_WRONG_STATE;
    }
    /* First need to verify the remote report */

    unsigned char remote_pk[crypto_kx_PUBLICKEYBYTES];
    ocall_receive_remote_report((void*)msg, sizeof(generic_channel_msg_t) + REPORT_LEN, remote_pk, crypto_kx_PUBLICKEYBYTES);

    cstring* temp_channel_id = cstr_new_buf(TEMPORARY_CHANNEL_ID, CHANNEL_ID_LEN);
    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    channel_state_t* channel_state = get_channel_state(temp_channel_id->str);
    
    remove_association(temp_channel_id->str);
    associate_channel_state(channel_id->str, channel_state);
    remote_channel_establish(channel_state, remote_pk);

    int size = sizeof(ocall_channel_msg_t) + REPORT_LEN;
    ocall_channel_msg_t* ocall_msg = (ocall_channel_msg_t*)malloc(size);
    memcpy(ocall_msg->blob, report_buffer, REPORT_LEN);
    memcpy(ocall_msg->channel_id, channel_id->str, CHANNEL_ID_LEN);
    ocall_msg->sockfd = remote_sockfd;
    ocall_create_channel_connected((void*)ocall_msg, size);
    free(ocall_msg);
    cstr_free(temp_channel_id, true);
    cstr_free(channel_id, true);
    return RES_SUCCESS;
}

int ecall_remote_channel_connected_ack(generic_channel_msg_t* msg) {

    if (check_state(Funded) != 0 && check_state(Backup) != 0) {
        ocall_print_buffer("Cannot set the channel id; this enclave is not in the correct state!\n");
        return RES_WRONG_STATE;
    }
    unsigned char remote_pk[crypto_kx_PUBLICKEYBYTES];
    ocall_receive_remote_report_ack((void*)msg, sizeof(generic_channel_msg_t) + REPORT_LEN, remote_pk, crypto_kx_PUBLICKEYBYTES);

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    channel_state_t* channel_state = get_channel_state(channel_id->str);
    remote_channel_establish(channel_state, remote_pk);
    send_channel_create_data(channel_state);

    cstr_free(channel_id, true);
    return RES_SUCCESS;
}

void process_verify_deposits_ack(channel_state_t* channel_state) {

    if (check_status(channel_state, Unverified) != 0) {
        ocall_print_buffer("Cannot verify deposits for channel; channel is not in the correct state!\n");
    }

    channel_state->other_party_deposits_verified = 1;

    if (channel_state->deposits_verified) {
        channel_state->status = Alive;
    }
}

void send_on_channel(int operation, channel_state_t* channel_state, unsigned char *msg, size_t msg_len) {
    
    size_t ct_size;
    unsigned long start = getcycles();
    unsigned char* ct_msg = remote_channel_box(channel_state, msg, msg_len, &ct_size);
    unsigned long end = getcycles();
    PRINTF("total cycles to encrypt %d bytes: %lu.\n", msg_len, end - start);

    int size = sizeof(generic_channel_msg_t) + ct_size;
    generic_channel_msg_t* ocall_msg = (generic_channel_msg_t*)malloc(size);
    memcpy(ocall_msg->blob, ct_msg, ct_size);
    memcpy(ocall_msg->channel_id, channel_state->channel_id, CHANNEL_ID_LEN);
    ocall_msg->msg_op = operation;

    ocall_send_on_channel((void*)ocall_msg, size);
    free(ocall_msg);
    free(ct_msg);
}

void send_channel_create_data(channel_state_t* channel_state) {

    struct channel_init_msg_t msg;
    memcpy(msg.channel_id, channel_state->channel_id, CHANNEL_ID_LEN);
    memcpy(msg.bitcoin_address, my_setup_transaction.my_address, BITCOIN_ADDRESS_LEN);
    msg.num_deposits = my_setup_transaction.num_deposits;
    for (unsigned long long i = 0; i < my_setup_transaction.num_deposits; i++) {
        deposit_t* deposit = map_get(&my_setup_transaction.deposit_ids_to_deposits, ulltostr(i));

        memcpy(msg.deposits[i].txid, deposit->txid, BITCOIN_TX_HASH_LEN);
        msg.deposits[i].tx_idx = deposit->tx_idx;
        msg.deposits[i].deposit_amount = deposit->deposit_amount;

        memcpy(msg.deposits[i].deposit_bitcoin_address, deposit->bitcoin_address, BITCOIN_ADDRESS_LEN);
        memcpy(msg.deposits[i].deposit_public_keys, deposit->public_key, BITCOIN_PUBLIC_KEY_LEN);
        memcpy(msg.deposits[i].deposit_private_keys, deposit->private_key, BITCOIN_PRIVATE_KEY_LEN);
    }

    send_on_channel(OP_REMOTE_CHANNEL_CREATE_DATA, channel_state, (unsigned char*)&msg, sizeof(channel_init_msg_t));
}

void process_channel_create_data(channel_state_t* channel_state, channel_init_msg_t* msg) {

    cstring* channel_id = cstr_new_buf(channel_state->channel_id, CHANNEL_ID_LEN);
    PRINTF("A channel has been created!\n"
            "Channel ID: %s\n"
            "The remote has presented their funding deposits. Please verify the following unspent transaction outputs are in the blockchain.\n"
            "Number of outputs: %d.\n", channel_id->str, msg->num_deposits);
    
    map_init(&channel_state->remote_setup_transaction.deposit_ids_to_deposits);
    
    for (unsigned long long i = 0; i < msg->num_deposits; i++) {
        deposit_t deposit;
        
        memcpy(deposit.txid, msg->deposits[i].txid, BITCOIN_TX_HASH_LEN);
        deposit.tx_idx = msg->deposits[i].tx_idx;
        deposit.deposit_amount = msg->deposits[i].deposit_amount;

        memcpy(deposit.bitcoin_address, msg->deposits[i].deposit_bitcoin_address, BITCOIN_ADDRESS_LEN);
        deposit.bitcoin_address[BITCOIN_ADDRESS_LEN] = '\0';
        memcpy(deposit.public_key, msg->deposits[i].deposit_public_keys, BITCOIN_PUBLIC_KEY_LEN);
        memcpy(deposit.private_key, msg->deposits[i].deposit_private_keys, BITCOIN_PRIVATE_KEY_LEN);
        map_set(&channel_state->remote_setup_transaction.deposit_ids_to_deposits, ulltostr(i), deposit);
        PRINTF("Transaction ID: %s, Deposit index %d should pay %d satoshi into address %s.\n", deposit.txid, deposit.tx_idx, deposit.deposit_amount, deposit.bitcoin_address);
    }

    memcpy(channel_state->remote_setup_transaction.my_address, msg->bitcoin_address, BITCOIN_ADDRESS_LEN);
    channel_state->remote_setup_transaction.num_deposits = msg->num_deposits;
    channel_state->remote_balance = 0;
    if (channel_state->is_initiator == 0) {
        send_channel_create_data(channel_state);
    }
    cstr_free(channel_id, true);
}

vector* find_deposit_ids_in_channel(char* channel_id) {

    btc_bool res;
    const char* key;
    vector* vec = vector_new(10, NULL);

    map_iter_t iter = map_iter(&my_setup_transaction.deposit_ids_to_channels);
    while ((key = map_next(&my_setup_transaction.deposit_ids_to_channels, &iter))) {
        char* val = *map_get(&my_setup_transaction.deposit_ids_to_channels, key);
        if (streq(channel_id, val)) {
            res = vector_add(vec, (void*)key);
            if (res != true) {
                ocall_print_buffer("fail to add to vector.\n");
            }
        }
    }
    return vec;
}

int ecall_balance(generic_channel_msg_t* msg) {

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    channel_state_t* state = get_channel_state(channel_id->str);

    if (check_status(state, Alive) != 0) {
        ocall_print_buffer("Cannot display balance for channel; channel is not in the correct state!\n");
        return RES_WRONG_CHANNEL_STATE;
    }

    vector* deposit_ids_in_channel = find_deposit_ids_in_channel(channel_id->str);

    PRINTF("Printing balance and deposits for channel: %s.\n", channel_id->str);
    unsigned int num = deposit_ids_in_channel->len;
    if (num == 0) {
        ocall_print_buffer("You have no deposits in this channel.\n");
    } else {
        PRINTF("You have %d deposits in this channel.\n", num);
        for (unsigned int i = 0; i < num; i++) {
            char* deposit_idx = vector_idx(deposit_ids_in_channel, i);
            deposit_t* deposit = map_get(&my_setup_transaction.deposit_ids_to_deposits, deposit_idx);
            PRINTF("Deposit index: %s, amount: %d (satoshi).\n", deposit_idx, deposit->deposit_amount);
        }
    }
    PRINTF("My balance is: %d, remote balance is: %d (satoshi).\n", state->my_balance, state->remote_balance);
    cstr_free(channel_id, true);
    return RES_SUCCESS;
}

int is_deposit_spent(int deposit_id) {

    deposit_t* deposit = map_get(&my_setup_transaction.deposit_ids_to_deposits, ulltostr((unsigned long long)deposit_id));
    if (deposit->is_spent) {
        return true;
    }
    return false;
}

char* is_deposit_in_use(map_str_t* deposit_ids_to_channels, int deposit_id) {

    if (!map_get(deposit_ids_to_channels, ulltostr((unsigned long long)deposit_id))) {
        return NULL;
    }
    return *map_get(deposit_ids_to_channels, ulltostr((unsigned long long)deposit_id));
}

void send_add_deposit(channel_state_t* channel_state, unsigned long long deposit_id) {

    btc_bool res;
    do {
        res = btc_random_bytes((uint8_t*)channel_state->most_recent_nonce, NONCE_BYTE_LEN, 0);
    } while (!res);
    struct remote_deposit_msg_t msg;
    msg.deposit_operation = ADD_DEPOSIT;
    memcpy(msg.nonce, channel_state->most_recent_nonce, NONCE_BYTE_LEN);
    memcpy(msg.channel_id, channel_state->channel_id, CHANNEL_ID_LEN);
    msg.deposit_id = deposit_id;

    send_on_channel(OP_REMOTE_TEECHAIN_DEPOSIT_ADD, channel_state, (unsigned char*)&msg, sizeof(remote_deposit_msg_t));
}

int ecall_add_deposit_to_channel(deposit_msg_t* msg) {

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    unsigned long long deposit_id = msg->deposit_id;
    channel_state_t* state = get_channel_state(channel_id->str);

    if (check_status(state, Alive) != 0) {
        ocall_print_buffer("cannot add deposit to channel; channel is not in the correct state!\n");
        return RES_WRONG_CHANNEL_STATE;
    }

    if (deposit_id >= my_setup_transaction.num_deposits) {
        ocall_print_buffer("invalid deposit_id!\n");
        return RES_WRONG_ARGS;
    }

    // check deposit not already spent
    if (is_deposit_spent(deposit_id)) {
        ocall_print_buffer("deposit has already been spent!\n");
        return RES_WRONG_STATE;
    }

    // check deposit not already in use
    if (is_deposit_in_use(&my_setup_transaction.deposit_ids_to_channels, deposit_id) != NULL) {
        ocall_print_buffer("deposit already in use!\n");
        return RES_WRONG_STATE;
    }

    map_set(&my_setup_transaction.deposit_ids_to_channels, ulltostr((unsigned long long) deposit_id), channel_id->str);
    deposit_t* deposit = map_get(&my_setup_transaction.deposit_ids_to_deposits, ulltostr((unsigned long long) deposit_id));
    state->my_balance += deposit->deposit_amount;

    PRINTF("Added deposit %d to channel %s.\n"
            "My balance is now: %d, remote balance is: %d (satoshi).\n", deposit_id, channel_id->str, state->my_balance, state->remote_balance);
    
    send_add_deposit(state, deposit_id);
    return RES_SUCCESS;
}

void send_add_deposit_ack(channel_state_t* channel_state, unsigned long long deposit_id, char* nonce) {
    
    struct secure_ack_msg_t ack;
    memcpy(ack.channel_id, channel_state->channel_id, CHANNEL_ID_LEN);
    memcpy(ack.nonce, nonce, NONCE_BYTE_LEN);
    ack.result = ADD_DEPOSIT_ACK;

    send_on_channel(OP_REMOTE_TEECHAIN_DEPOSIT_ADD_ACK, channel_state, (unsigned char*)&ack, sizeof(secure_ack_msg_t));
}

void process_deposit_add(channel_state_t* channel_state, remote_deposit_msg_t* msg) {

    if (msg->deposit_operation != ADD_DEPOSIT) {
        ocall_print_buffer("invalid deposit operation!\n");
    }

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);

    char* nonce = (char*)malloc(NONCE_BYTE_LEN);
    memcpy(nonce, msg->nonce, NONCE_BYTE_LEN);
    unsigned long long deposit_id_to_add = msg->deposit_id;

    if (deposit_id_to_add >= channel_state->remote_setup_transaction.num_deposits) {
        ocall_print_buffer("invalid deposit_id!\n");
    }

    map_set(&channel_state->remote_setup_transaction.deposit_ids_to_channels, ulltostr(deposit_id_to_add), channel_id->str);
    deposit_t* deposit = map_get(&channel_state->remote_setup_transaction.deposit_ids_to_deposits, ulltostr(deposit_id_to_add));
    channel_state->remote_balance += deposit->deposit_amount;

    send_add_deposit_ack(channel_state, deposit_id_to_add, nonce);
    free(nonce);
}

int check_message_nonce(channel_state_t* channel_state, char* message_nonce) {

    cstring* nonce = cstr_new_buf(message_nonce, NONCE_BYTE_LEN);
    if (!streq(channel_state->most_recent_nonce, nonce->str)) {
        PRINTF("Invalid message nonce! Current: %s, Given: %s.\n", channel_state->most_recent_nonce, nonce->str);
        return false;
    }
    cstr_free(nonce, true);
    return true;
}

void process_deposit_add_ack(channel_state_t* channel_state, secure_ack_msg_t* msg) {

    check_message_nonce(channel_state, msg->nonce);

    if (msg->result != ADD_DEPOSIT_ACK) {
        ocall_print_buffer("process_deposit_add_ack: invalid ack response.\n");
    }
}

void remove_deposit_from_channel(map_str_t* deposit_ids_to_channels, unsigned long long deposit_id) {
    map_remove(deposit_ids_to_channels, ulltostr(deposit_id));
}

void send_remove_deposit(channel_state_t* channel_state, unsigned long long deposit_id) {

    btc_bool res;
    do {
        res = btc_random_bytes((uint8_t*)channel_state->most_recent_nonce, NONCE_BYTE_LEN, 0);
    } while (!res);
    struct remote_deposit_msg_t msg;
    msg.deposit_operation = REMOVE_DEPOSIT;
    memcpy(msg.nonce, channel_state->most_recent_nonce, NONCE_BYTE_LEN);
    memcpy(msg.channel_id, channel_state->channel_id, CHANNEL_ID_LEN);
    msg.deposit_id = deposit_id;

    send_on_channel(OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE, channel_state, (unsigned char*)&msg, sizeof(remote_deposit_msg_t));
}

int ecall_remove_deposit_from_channel(deposit_msg_t* msg) {

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    unsigned long long deposit_id = msg->deposit_id;
    channel_state_t* state = get_channel_state(channel_id->str);

    if (check_status(state, Alive) != 0) {
        ocall_print_buffer("cannot add deposit to channel; channel is not in the correct state!\n");
        return RES_WRONG_CHANNEL_STATE;
    }

    if (deposit_id >= my_setup_transaction.num_deposits) {
        ocall_print_buffer("invalid deposit_id!\n");
        return RES_WRONG_ARGS;
    }

    char* p = is_deposit_in_use(&my_setup_transaction.deposit_ids_to_channels, deposit_id);
    if (p == NULL || !streq(p, channel_id->str)) {
        ocall_print_buffer("deposit removal failed: channel is incorrect!\n");
        return RES_WRONG_CHANNEL_STATE;
    }

    deposit_t* deposit = map_get(&my_setup_transaction.deposit_ids_to_deposits, ulltostr((unsigned long long) deposit_id));
    if (state->my_balance < deposit->deposit_amount) {
        PRINTF("balance is too low to remove deposit! Balance in channel: %llu, Amount to remove: %llu.\n", state->my_balance, deposit->deposit_amount);
        return RES_WRONG_CHANNEL_STATE;
    }

    remove_deposit_from_channel(&my_setup_transaction.deposit_ids_to_channels, deposit_id);
    state->my_balance -= deposit->deposit_amount;

    PRINTF("Removed deposit %d from channel %s.\n"
            "My balance is now: %d, remote balance is: %d (satoshi).\n", deposit_id, channel_id->str, state->my_balance, state->remote_balance);
    
    send_remove_deposit(state, deposit_id);
    cstr_free(channel_id, true);

    return RES_SUCCESS;
}

void send_remove_deposit_ack(channel_state_t* channel_state, unsigned long long deposit_id, char* nonce) {
    
    struct secure_ack_msg_t ack;
    memcpy(ack.channel_id, channel_state->channel_id, CHANNEL_ID_LEN);
    memcpy(ack.nonce, nonce, NONCE_BYTE_LEN);
    ack.result = REMOVE_DEPOSIT_ACK;

    send_on_channel(OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE_ACK, channel_state, (unsigned char*)&ack, sizeof(secure_ack_msg_t));
}

void process_deposit_remove(channel_state_t* channel_state, remote_deposit_msg_t* msg) {
    
    if (msg->deposit_operation != REMOVE_DEPOSIT) {
        ocall_print_buffer("invalid deposit operation!\n");
    }

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);

    char* nonce = (char*)malloc(NONCE_BYTE_LEN);
    memcpy(nonce, msg->nonce, NONCE_BYTE_LEN);
    unsigned long long deposit_id_to_remove = msg->deposit_id;

    if (deposit_id_to_remove >= channel_state->remote_setup_transaction.num_deposits) {
        ocall_print_buffer("invalid deposit_id!\n");
    }

    char* p = is_deposit_in_use(&channel_state->remote_setup_transaction.deposit_ids_to_channels, deposit_id_to_remove);
    if (p == NULL || !streq(p, channel_id->str)) {
        ocall_print_buffer("deposit removal failed: channel is incorrect!\n");
    }

    deposit_t* deposit = map_get(&channel_state->remote_setup_transaction.deposit_ids_to_deposits, ulltostr(deposit_id_to_remove));
    remove_deposit_from_channel(&channel_state->remote_setup_transaction.deposit_ids_to_channels, deposit_id_to_remove);
    channel_state->remote_balance -= deposit->deposit_amount;

    send_remove_deposit_ack(channel_state, deposit_id_to_remove, nonce);
    cstr_free(channel_id, true);
    free(nonce);
}

void process_deposit_remove_ack(channel_state_t* channel_state, secure_ack_msg_t* msg) {
    
    check_message_nonce(channel_state, msg->nonce);

    if (msg->result != REMOVE_DEPOSIT_ACK) {
        ocall_print_buffer("process_deposit_remove_ack: invalid ack response.\n");
    }
}

void send_bitcoin_payment(channel_state_t* channel_state, unsigned long long amount) {

    struct remote_send_msg_t msg;

    channel_state->my_monotonic_counter += 1;
    channel_state->my_sends += 1;

    msg.monotonic_count = channel_state->my_monotonic_counter;
    msg.amount = amount;

    send_on_channel(OP_REMOTE_SEND, channel_state, (unsigned char*)&msg, sizeof(remote_send_msg_t));
}

int ecall_send(send_msg_t* msg) {

    start0 = getcycles();
    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    unsigned long long amount = msg->amount;
    channel_state_t* state = get_channel_state(channel_id->str);

    if (check_status(state, Alive) != 0) {
        ocall_print_buffer("Cannot send on channel; channel is not in the correct state!\n");
        send_reply(RES_WRONG_CHANNEL_STATE);
    }

    if (amount <= 0 || amount > state->my_balance) {
        PRINTF("Cannot send amount %d, balance is %d.\n", amount, state->my_balance);
        send_reply(RES_WRONG_ARGS);
    }

    state->my_balance -= amount;
    state->remote_balance += amount;

    send_bitcoin_payment(state, amount);
    cstr_free(channel_id, true);
    return RES_SUCCESS;
}

int check_deposits_verified(channel_state_t* channel_state) {
    return channel_state->deposits_verified && channel_state->other_party_deposits_verified;
}

void send_send_ack(channel_state_t* channel_state) {
    send_on_channel(OP_REMOTE_SEND_ACK, channel_state, NULL, 0);
}

void process_send(channel_state_t* channel_state, remote_send_msg_t* msg){
    
    cstring* channel_id = cstr_new_buf(channel_state->channel_id, CHANNEL_ID_LEN);
    if (!check_deposits_verified(channel_state)) {
        ocall_print_buffer("Channel is not established by both parties! Cannot send bitcoins!\n");
    }

    if (msg->monotonic_count <= channel_state->remote_last_seen) {
        ocall_print_buffer("Replayed request: we have seen later messages.\n");
    }

    channel_state->remote_last_seen = msg->monotonic_count;
    channel_state->my_balance += msg->amount;
    channel_state->remote_balance -= msg->amount;
    channel_state->my_receives += 1;

    if (!benchmark) {
        PRINTF("Received %d satoshi on channel: %s.\n"
            "My balance is now: %d, remote balance is: %d (satoshi).\n", msg->amount, channel_id->str, channel_state->my_balance, channel_state->remote_balance);
    }

    send_send_ack(channel_state);

    cstr_free(channel_id, true);
}

void process_send_ack(channel_state_t* channel_state) {
    
    send_reply(OP_ACK);
    if (!benchmark) {
        ocall_print_buffer("Your payment has been sent!\n");
    }
    end0 = getcycles();
    PRINTF("total cycles to send: %lu.\n", end0 - start0);
}

int ecall_profile() {

    unsigned long start = getcycles();
    ocall_profile();
    unsigned long end = getcycles();
    PRINTF("total cycles to ocall: %lu.\n", end - start);
    return RES_SUCCESS;
}

int ecall_round_trip(send_msg_t* msg) {
    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    channel_state_t* state = get_channel_state(channel_id->str);
    start0 = getcycles();
    send_on_channel(OP_ROUND_TRIP0, state, NULL, 0);
    return RES_SUCCESS;
}

void process_round_trip0(channel_state_t* channel_state) {
    send_on_channel(OP_ROUND_TRIP1, channel_state, NULL, 0);
}

void process_round_trip1(channel_state_t* channel_state) {
    end0 = getcycles();
    PRINTF("total cycles to round trip: %lu.\n", end0 - start0);
}

unsigned long getcycles() {
    /* We will just return cycle count for now */
    unsigned long cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));

    return cycles;
}