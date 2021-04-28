#include "teechain.h"
#include "state.h"
#include "utils.h"

// keystone
#include "edge_wrapper.h"
#include "string.h"

// libbtc
#include "btc.h"
#include "cstr.h"
#include "ecc.h"
#include "ecc_key.h"
#include "script.h"
#include "tool.h"
#include "chainparams.h"
#include "debug.h"

const btc_chainparams *chain = &btc_chainparams_test;

// Global setup transaction for this enclave
setup_transaction_t my_setup_transaction;

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

int ecall_setup_deposits(setup_deposits_msg_t msg) {
    
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

    PRINTF("Please deposit into bitcoin addresses below:\n");

    // generate and print bitcoin addresses to be paid into by the user
    for (unsigned long long i = 0; i < msg.num_deposits; i++) {
        // create new deposit
        deposit_t* deposit = (deposit_t *)malloc(sizeof(deposit_t));
        deposit->is_spent = 0;
        deposit->deposit_amount = 0;
        
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

        memcpy(deposit->bitcoin_address, address_p2pkh, strlen(address_p2pkh));
        memcpy(deposit->public_key, pubkey.pubkey, pubkey.compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);
        memcpy(deposit->private_key, key.privkey, BTC_ECKEY_PKEY_LENGTH);

        btc_privkey_cleanse(&key);
        btc_pubkey_cleanse(&pubkey);

        map_set(&my_setup_transaction.deposit_ids_to_deposits, ulltostr(i), deposit);
        PRINTF("%s\n", address_p2pkh);

        memset(privkey_wif, 0, strlen(privkey_wif));
        memset(pubkey_hex, 0, strlen(pubkey_hex));
        
        memset(address_p2pkh, 0, strlen(address_p2pkh));
    }

    teechain_state = WaitingForFunds;

    cstr_free(p2pkh, 1);
    return RES_SUCCESS;
}