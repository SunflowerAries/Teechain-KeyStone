#include <iomanip>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <map>
#include <vector>

#include "channel.h"
#include "encl_message.h"

struct connection_t connections[MAXCONN];
struct epoll_event event;
struct epoll_event events[MAX_EVENTS];

std::map<std::string, channel_state_t*> channel_states;

void init_channel_connection(channel_connection_t* connection) {
    memcpy((char*)connection->id, "", 1);
    memcpy((char*)connection->remote_host, "", 1);
    connection->remote_host_len = 0;
    connection->remote_port = -1;
    connection->remote_sockfd = -1;
}

void init_channel_state(channel_state_t* state) {
    init_channel_connection(&state->connection);
    state->enclave_lost_retry_time = 1;
    state->busy_retry_time = 4;
    state->is_initiator = false;   
}

channel_state_t* create_channel_state() {
    channel_state_t* state = (channel_state_t*) malloc(sizeof(channel_state_t));
    init_channel_state(state);
    return state;
}

channel_state_t* get_channel_state(std::string channel_id) {
    std::map<std::string, channel_state_t*>::iterator it = channel_states.find(channel_id);
    if (it == channel_states.end()) {
        printf("Untrusted get_channel_state() could not find channel state for given channel_id %s.\n", channel_id.c_str());
        printf("Printing contents of channel states!");
        for (std::map<std::string, channel_state_t*>::const_iterator it = channel_states.begin(); it != channel_states.end(); it++) {
            printf(it->first.c_str());
        }
        return NULL;
    }
    return it->second;
}

void associate_channel_state(std::string channel_id, channel_state_t* state_to_associate) {
    memcpy((char*) state_to_associate->connection.id, channel_id.c_str(), CHANNEL_ID_LEN);
    channel_states.insert(std::pair<std::string, channel_state_t*>(channel_id, state_to_associate));
}

void remove_association(std::string channel_id) {
    channel_states.erase(channel_id);
}

int connect_to_socket(std::string socket_hostname, int socket_port) {
    struct addrinfo* addr;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", socket_port);
    
    if (getaddrinfo(socket_hostname.c_str(), port_str, 0, &addr) < 0) {
        printf("getaddrinfo");
    }

    struct addrinfo* p;
    int sockfd;
    for (p = addr; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, SOCK_STREAM, 0)) < 0) {
            continue;
        }
        
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
            close(sockfd);
            continue;
        }
        break;
    }

    if (p == NULL) {
        printf("Error when connecting.\n");
    }
    return sockfd;
}

void send_on_socket(char* msg, size_t msglen, int sockfd) {
    write(sockfd, &msglen, sizeof(size_t));
    write(sockfd, msg, msglen);
}

// sends the given message on the socket, with the appropriate message operation
void send_message(uint32_t operation, char *channel_id, void* blob_pointer, int blob_size, int sockfd) {
    size_t msg_len = sizeof(struct generic_channel_msg_t) + blob_size;
    generic_channel_msg_t* msg = (generic_channel_msg_t*)malloc(msg_len);
    msg->msg_op = operation;
    memcpy(msg->channel_id, channel_id, CHANNEL_ID_LEN);
    memcpy(msg->blob, blob_pointer, blob_size);
    send_on_socket((char*)msg, msg_len, sockfd);
    free(msg);
}