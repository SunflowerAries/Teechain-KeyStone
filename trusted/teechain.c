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
#include "ecc.h"
#include "ecc_key.h"
#include "script.h"
#include "tool.h"
#include "chainparams.h"

const btc_chainparams *chain = &btc_chainparams_test;

// Global setup transaction for this enclave
setup_transaction_t my_setup_transaction;

unsigned int num_deposits;

void teechain_init() {
    btc_ecc_start();
    ocall_print_buffer("Before map_init.\n");
    map_init(&my_setup_transaction.deposit_ids_to_channels);
    map_init(&my_setup_transaction.deposit_ids_to_deposits);
}

int ecall_primary() {

    if (check_state(Ghost) != 0) {
        ocall_print_buffer("Cannot assign this node as primary; not in the correct state!\n");
        return RES_WRONG_STATE;
    }
    teechain_state = Primary;
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

        memcpy(deposit.bitcoin_address, address_p2pkh, strlen(address_p2pkh));
        memcpy(deposit.public_key, pubkey.pubkey, pubkey.compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);
        memcpy(deposit.private_key, key.privkey, BTC_ECKEY_PKEY_LENGTH);

        btc_privkey_cleanse(&key);
        btc_pubkey_cleanse(&pubkey);

        map_set(&my_setup_transaction.deposit_ids_to_deposits, ulltostr(i), deposit);
        num_deposits++;
        PRINTF("%s\n", address_p2pkh);

        memset(privkey_wif, 0, strlen(privkey_wif));
        memset(pubkey_hex, 0, strlen(pubkey_hex));
        
        memset(address_p2pkh, 0, strlen(address_p2pkh));
    }

    teechain_state = WaitingForFunds;

    cstr_free(p2pkh, 1);
    return RES_SUCCESS;
}

int ecall_deposits_made(deposits_made_msg_t* msg) {
    // if (check_state(WaitingForFunds) != 0) {
    //     ocall_print_buffer("Cannot make the deposits into the enclave; setup deposits hasn't been called!");
    //     return RES_WRONG_STATE;
    // }

    // if (num_deposits != msg->num_deposits) {
    //     ocall_print_buffer("Number of deposits made does not match the number given to ecall_setup_deposits");
    //     return RES_WRONG_ARGS;
    // }

    // store enclave state for Setup transaction
    memcpy(my_setup_transaction.my_address, msg->my_address, BITCOIN_ADDRESS_LEN);
    my_setup_transaction.miner_fee = msg->miner_fee;

    // store deposit information for setup transaction and 
    for (unsigned long long i = 0; i < num_deposits; i++) {
        // update deposit amount and script
        deposit_t* deposit = map_get(&my_setup_transaction.deposit_ids_to_deposits, ulltostr(i));
        memcpy(deposit->txid, msg->deposits[i].txid, BITCOIN_TX_HASH_LEN);
        deposit->tx_idx = msg->deposits[i].tx_idx;
        deposit->deposit_amount = msg->deposits[i].deposit_amount;
    }

    teechain_state = Funded;
    PRINTF("Loaded %u funding deposits into the Enclave.\nYou are ready to begin creating channels!\n", num_deposits);
    return RES_SUCCESS;
}

int ecall_create_channel(create_channel_msg_t* msg) {
    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);

    // if (check_state(Funded) != 0) {
    //     ocall_print_buffer("Cannot create new channel; this enclave is not funded!");
    //     return RES_WRONG_STATE;
    // }

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
    cstr_free(channel_id, 1);
    return RES_SUCCESS;
}

int ecall_verify_deposits(generic_channel_msg_t* msg) {
    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    channel_state_t *state = get_channel_state(channel_id->str);

    if (check_status(state, Unverified) != 0) {
        PRINTF("Cannot verify deposits for channel; channel is not in the correct state!");
        return RES_WRONG_CHANNEL_STATE;
    }

    state->deposits_verified = 1;

    if (state->other_party_deposits_verified) {
        state->status = Alive;
    }

    PRINTF("You have verified the funding transaction of the remote party in channel: %s\n", channel_id->str);
    cstr_free(channel_id, 1);
    return RES_SUCCESS;
}

int ecall_remote_channel_connected(generic_channel_msg_t* msg, int remote_sockfd) {
    /*
     if (check_state(Funded) != 0 && check_state(Backup) != 0) {
        PRINTF("Cannot set the channel id; this enclave is not in the correct state!");
        return RES_WRONG_STATE;
    }
    */
    /* First need to verify the remote report */


    unsigned char pk[crypto_kx_PUBLICKEYBYTES];
    ocall_receive_remote_report((void*)msg, sizeof(generic_channel_msg_t) + REPORT_LEN, pk, crypto_kx_PUBLICKEYBYTES);

    cstring* temp_channel_id = cstr_new_buf(TEMPORARY_CHANNEL_ID, CHANNEL_ID_LEN);
    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    channel_state_t* channel_state = get_channel_state(temp_channel_id->str);
    
    remove_association(temp_channel_id->str);
    associate_channel_state(channel_id->str, channel_state);
    remote_channel_establish(channel_state, pk);

    int size = sizeof(ocall_channel_msg_t) + REPORT_LEN;
    ocall_channel_msg_t* ocall_msg = (ocall_channel_msg_t*)malloc(size);
    memcpy(ocall_msg->blob, report_buffer, REPORT_LEN);
    memcpy(ocall_msg->channel_id, channel_id->str, CHANNEL_ID_LEN);
    ocall_msg->sockfd = remote_sockfd;
    ocall_create_channel_connected((void*)ocall_msg, size);
    free(ocall_msg);
    cstr_free(temp_channel_id, 1);
    cstr_free(channel_id, 1);
    return RES_SUCCESS;
}

int ecall_remote_channel_connected_ack(generic_channel_msg_t* msg) {
    /*
    if (check_state(Funded) != 0 && check_state(Backup) != 0) {
        PRINTF("Cannot set the channel id; this enclave is not in the correct state!");
        return RES_WRONG_STATE;
    }
    */
    unsigned char pk[crypto_kx_PUBLICKEYBYTES];
    ocall_receive_remote_report_ack((void*)msg, sizeof(generic_channel_msg_t) + REPORT_LEN, pk, crypto_kx_PUBLICKEYBYTES);

    cstring* channel_id = cstr_new_buf(msg->channel_id, CHANNEL_ID_LEN);
    channel_state_t* channel_state = get_channel_state(channel_id->str);
    remote_channel_establish(channel_state, pk);
    ecall_remote_channel_init(channel_state);

    cstr_free(channel_id, 1);
    return RES_SUCCESS;
}

static void send_on_channel(int operation, channel_state_t* channel_state, unsigned char *msg, size_t msg_len) {
    size_t ct_size;
    unsigned char* ct_msg = remote_channel_box(channel_state, msg, msg_len, &ct_size);

    int size = sizeof(generic_channel_msg_t) + ct_size;
    generic_channel_msg_t* ocall_msg = (generic_channel_msg_t*)malloc(size);
    memcpy(ocall_msg->blob, ct_msg, ct_size);
    memcpy(ocall_msg->channel_id, channel_state->channel_id, CHANNEL_ID_LEN);
    ocall_msg->msg_op = operation;

    ocall_send_on_channel((void*)ocall_msg, size);
    free(ocall_msg);
    free(ct_msg);
}

void ecall_remote_channel_init(channel_state_t* channel_state) {
    struct channel_init_msg_t msg;
    memcpy(msg.channel_id, channel_state->channel_id, CHANNEL_ID_LEN);
    memcpy(msg.bitcoin_address, my_setup_transaction.my_address, BITCOIN_ADDRESS_LEN);
    msg.num_deposits = num_deposits;
    for (unsigned long long i = 0; i < num_deposits; i++) {
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

void ecall_remote_channel_init_ack(channel_state_t* channel_state, channel_init_msg_t* msg) {

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
        memcpy(deposit.public_key, msg->deposits[i].deposit_public_keys, BITCOIN_PUBLIC_KEY_LEN);
        memcpy(deposit.private_key, msg->deposits[i].deposit_private_keys, BITCOIN_PRIVATE_KEY_LEN);
        map_set(&channel_state->remote_setup_transaction.deposit_ids_to_deposits, ulltostr(i), deposit);
        PRINTF("Transaction ID: %s, Deposit index %d should pay %d satoshi into address %s.\n", deposit.txid, deposit.tx_idx, deposit.deposit_amount, deposit.bitcoin_address);
    }

    memcpy(channel_state->remote_setup_transaction.my_address, msg->bitcoin_address, BITCOIN_ADDRESS_LEN);
    channel_state->remote_balance = 0;
    if (channel_state->is_initiator == 0) {
        ecall_remote_channel_init(channel_state);
    }
}