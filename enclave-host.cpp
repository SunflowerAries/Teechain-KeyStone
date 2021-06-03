#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include "keystone.h"
#include "edge_wrapper.h"
#include "encl_message.h"
#include "channel.h"

#define PRINT_MESSAGE_BUFFERS 1
#define TEECHAN_SEC_FILENAME "trusted_teechain.riscv"
#define RUNTIME_PATH "eyrie-rt"

#define DEFAULT_PORT 8067
#define BUFFERLEN 4096

#define MAX_BACKLOG 50
#define MAX_CONNECTIONS 50

byte local_buffer[BUFFERLEN];
int epoll_fd = -1;
int fd_sock;
int fd_clientsock;

void send_buffer(byte* buffer, size_t len) {
    write(fd_clientsock, &len, sizeof(size_t));
    write(fd_clientsock, buffer, len);
}

byte* recv_buffer(size_t* len) {
    read(fd_clientsock, local_buffer, sizeof(size_t));
    size_t reply_size = *(size_t*)local_buffer;
    byte* reply = (byte*)malloc(reply_size);
    read(fd_clientsock, reply, reply_size);
    *len = reply_size;
    return reply;
}

byte* recv_on_socket(size_t* len, int sockfd) {
    read(sockfd, local_buffer, sizeof(size_t));
    size_t reply_size = *(size_t*)local_buffer;
    byte* reply = (byte*)malloc(reply_size);
    read(sockfd, reply, reply_size);
    *len = reply_size;
    return reply;
}

void print_hex_data(unsigned char* data, size_t len) {
    unsigned int i;
    std::string str;
    for (i = 0; i < len; i += 1) {
        std::stringstream ss;
        ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)data[i];
        str += ss.str();
        if(i > 0 && (i + 1) % 8 == 0){
            if ((i + 1) % 32 == 0) {
                str += "\n";
            } else {
                str += " ";
            }
        }
    }
    printf("%s\n\n",str.c_str());
}

unsigned long print_buffer(char* str) {
    printf("[TT] %s",str);
    return strlen(str);
}

void print_value(unsigned long val) {
    printf("[TT] value: %u\n",val);
    return;
}

void send_reply(void* data, size_t len) {
    printf("[EH] Sending encrypted reply:\n");

    if (PRINT_MESSAGE_BUFFERS) {
        print_hex_data((unsigned char*)data, len);
    }

    send_buffer((byte*)data, len);
}

void* wait_for_client_pubkey() {
    size_t len;
    return recv_buffer(&len);
}

void send_report(void* buffer, size_t len) {
    send_buffer((byte*)buffer, len);
}

void register_new_connection(int conn_sock) {
    event.events = EPOLLIN;
    event.data.fd = conn_sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_sock, &event) < 0) {
        printf("Failed to epoll_ctl");
        exit(-1);
    }

    // let's get the peer's IP address
    struct sockaddr_storage addr;
    char ipstr[INET6_ADDRSTRLEN];
    int remoteport, islocalhost = 0;

    socklen_t len = sizeof(addr);
    getpeername(conn_sock, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        remoteport = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
        islocalhost = (strcmp(ipstr, "127.0.0.1") == 0);
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        remoteport = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
        islocalhost = (strcmp(ipstr, "::1") == 0);
    }

    // TODO(joshlind): remove once we understand why getpeername
    // is returning the private IP instead of localhost?
    // printf("Peer IP address: %s\n", ipstr);
    if (!islocalhost) {
        islocalhost = (strcmp(ipstr, "192.168.0.101") == 0);
    } 

    // initialize a connection, indexed by the file descriptor
    connections[conn_sock].fd = conn_sock;
    connections[conn_sock].inuse = 1;
    connections[conn_sock].islocalhost = islocalhost;
}

static int accept_new_connection(int server) {
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    int conn_sock = accept(server, (struct sockaddr*)&client_addr, &addrlen);
    if (conn_sock < 0) {
        printf("No valid socket\n");
        exit(-1);
    }
    printf("successfully accept a socket, and before register_new_connection.\n");
    register_new_connection(conn_sock);
    return conn_sock;
}

static void* process_events(int epoll_wait_res, int server, size_t* len, int* sockfd) {
    *len = 0;
    for (int idx = 0; idx < epoll_wait_res; idx++) {
        int client_fd = events[idx].data.fd;
        if (client_fd == server) {
            accept_new_connection(server);
            continue;
        }

        if (events[idx].events & EPOLLIN) {
            void* buffer = recv_on_socket(len, client_fd);
            *sockfd = client_fd;
            return buffer;
        }
    }
    return NULL;
}

encl_message_t* wait_for_message(size_t* len) {
    int sockfd;

    int res = epoll_wait(epoll_fd, events, MAX_CONNECTIONS, -1);
    void* buffer = process_events(res, fd_sock, len, &sockfd);

    printf("[EH] Got an encrypted message with length(%d) from socket(%d):\n", *len, sockfd);
    if (PRINT_MESSAGE_BUFFERS) {
        print_hex_data((unsigned char*)buffer, *len);
    }

    /* This happens here */
    encl_message_t* message = (encl_message_t*)malloc(*len + sizeof(int));
    message->sockfd = sockfd;
    memcpy(message->payload, buffer, *len);
    *len += sizeof(int);
    return message;
}

void init_network_wait() {
    int optval = 1;
    struct sockaddr_in server_addr;

    fd_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_sock < 0) {
        printf("Failed to open socket\n");
        exit(-1);
    }

    if (setsockopt(fd_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0) {
        printf("Failed to set socket option\n");
        exit(-1);
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DEFAULT_PORT);
    if (bind(fd_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to bind socket\n");
        exit(-1);
    }
    listen(fd_sock, MAX_BACKLOG);

    epoll_fd = epoll_create(MAX_CONNECTIONS);
    if (epoll_fd < 0) {
        printf("Failed to create epoll\n");
        exit(-1);
    }

    event.events = EPOLLIN | EPOLLHUP;
    event.data.fd = fd_sock;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd_sock, &event) < 0) {
        printf("Failed to epoll_ctl\n");
    }

    epoll_wait(epoll_fd, events, MAX_CONNECTIONS, -1);
    fd_clientsock = accept_new_connection(fd_sock);
}

int main(int argc, char** argv) {
    /* Wait for network connection */
    init_network_wait();

    printf("[EH] Got connection from remote client\n");

    Keystone::Enclave enclave;
    Keystone::Params params;
    params.setFreeMemSize(48 * 1024 * 1024);

    if (enclave.init(TEECHAN_SEC_FILENAME, RUNTIME_PATH, params) != Keystone::Error::Success) {
        printf("HOST: Unable to start enclave\n");
        exit(-1);
    }

    edge_init(&enclave);

    Keystone::Error rval = enclave.run();
    printf("rval: %i\n",rval);

    return 0;
}
