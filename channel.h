#ifndef _CHANNEL_STATE_H_
#define _CHANNEL_STATE_H_

#include <string>
#include <sys/epoll.h>

// Temporary channel handle
#define TEMPORARY_CHANNEL_ID "0000011111111111111111111111111111111111111111111111111111100000"

// channel constants
#define CHANNEL_ID_LEN 16
#define REMOTE_HOST_LEN 128
#define REPORT_LEN 2048

#define MAX_EVENTS 10
#define MAXCONN 10000

#define OP_REMOTE_CHANNEL_CONNECTED 31  // the initiator generated the channel id (remote message) 
#define OP_REMOTE_CHANNEL_CONNECTED_ACK 32 // the receiver send back ack (remote message)
#define OP_REMOTE_CHANNEL_CREATE_DATA 33 // create a channel (remote message)

typedef struct connection_t {
    int fd;
    int inuse;
    int islocalhost;
} connection_t;

typedef struct channel_connection_t {
    const char remote_host[REMOTE_HOST_LEN];
	size_t remote_host_len;
	int remote_port;

	const char id[CHANNEL_ID_LEN];

	int remote_sockfd; // active communication socket with remote enclave
    int local_sockfd; // any local active communication socket (i.e. if a local command is waiting for an ack)
} channel_connection_t;

typedef struct ocall_create_channel_msg_t {
    char channel_id[CHANNEL_ID_LEN];
    char is_initiator;
    unsigned long long remote_host_len;
    char remote_host[REMOTE_HOST_LEN];
    unsigned long remote_port;
    unsigned char report_buffer[REPORT_LEN];
} ocall_create_channel_msg_t;

typedef struct channel_state_t {
    bool is_initiator;
    channel_connection_t connection;

    int enclave_lost_retry_time;
	int busy_retry_time;

} channel_state_t;

typedef struct ocall_channel_msg_t {
    int sockfd;
    char channel_id[CHANNEL_ID_LEN];
    char blob[];
} ocall_channel_msg_t;

typedef struct generic_channel_msg_t {
    char msg_op;
    char channel_id[CHANNEL_ID_LEN];
    char blob[];
} generic_channel_msg_t;

extern int fd_sock;
extern int epoll_fd;
extern struct epoll_event event;
extern struct epoll_event events[MAX_EVENTS];
extern struct connection_t connections[MAXCONN];

channel_state_t* create_channel_state();
void associate_channel_state(std::string channel_id, channel_state_t* state_to_associate);
channel_state_t* get_channel_state(std::string channel_id);
void remove_association(std::string channel_id);
int connect_to_socket(std::string socket_hostname, int socket_port);
void send_message(uint32_t operation, char *channel_id, void* blob_pointer, int blob_size, int sockfd);

#endif /* _CHANNEL_STATE_H_ */
