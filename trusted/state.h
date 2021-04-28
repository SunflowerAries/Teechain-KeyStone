#ifndef _STATE_H_
#define _STATE_H_

#include "map.h"

enum TeechanState {
	Ghost, // ghost enclave created

	Backup, // enclave is backup -- never changes state from this

	Primary, // enclave is assigned primary
	WaitingForFunds, // enclave is waiting for funding
	Funded, // enclave has been funded
};

typedef struct deposit_t {
    char is_spent;

    char bitcoin_address[128];
    char public_key[65];
    char private_key[32];

    char script[1024];

    char txid[64];
    unsigned long long tx_index;
    unsigned long long deposit_amount;

} deposit_t;

typedef map_t(deposit_t*) map_deposit_t;

typedef struct setup_transaction_t {
    // Input transaction information and keys to construct the setup transaction
    // std::string public_key;
    // std::string private_key;
    // std::string utxo_hash;
    unsigned long long utxo_index;
    // std::string utxo_script;

    // Setup transaction to place onto the blockchain
    // std::string setup_transaction_hash;

    // Assignments from deposit indexes to deposits
    map_deposit_t deposit_ids_to_deposits;

    // Assignments from deposit indexes to channel IDs
    map_str_t deposit_ids_to_channels;

    // Bitcoin address to pay when a channel is closed
    // std::string my_address;

    // Bitcoin miner fee to pay whenver I generate a transaction
    unsigned long long miner_fee;
} setup_transaction_t;

extern enum TeechanState teechain_state;
int check_state(enum TeechanState state);

#endif /* _STATE_H_ */