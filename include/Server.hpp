#pragma once
#include <iostream>
#include <cstdint>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class Server {
protected:
    int sockfd, web_sock;
    struct sockaddr_in address, local_address;
    int addrlen = sizeof(address);
    uint16_t port;
    SSL_CTX *ctx;
    socklen_t address_leng;
public:
  
    Server(std::string ip, std::string s_port);
    void initServer();
    
};
