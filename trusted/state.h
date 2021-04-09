#ifndef _STATE_H_
#define _STATE_H_

enum TeechanState {
	Ghost, // ghost enclave created

	Backup, // enclave is backup -- never changes state from this

	Primary, // enclave is assigned primary
	WaitingForFunds, // enclave is waiting for funding
	Funded, // enclave has been funded
};

extern TeechanState teechain_state;
bool check_state(TeechanState state);

#endif /* _STATE_H_ */