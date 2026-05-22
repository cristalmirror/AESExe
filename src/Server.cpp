#include "../include/Server.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <sys/socket.h>


//constructor
Server::Server(std::string ip, std::string s_port) {
    port = (uint16_t) std::stoul(s_port);
    ctx = SSL_CTX_new(TLS_server_method());
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    
}

// intialization of server
void Server::initServer() {

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (bind(sockfd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        std::cerr << "[AESEXE] {SERVER MODE}: ***Error in bind: Need root permissions to the port***" << std::endl;
        return;
    }

    address_leng = sizeof(local_address);

    if (getsockname(sockfd, (struct sockaddr *) &local_address, &address_leng)) {
        std::cerr << "[AESEXE] {SERVER MODE}: ***Error trying the configutaion socket***" << std::endl;
    } else {
        char *ip = inet_ntoa(local_address.sin_addr);
        uint16_t real_port = ntohs(local_address.sin_port);
        std::cout << "[AESEXE] {SERVER MODE}: Succesfull init server " << std::endl;
        std::cout << "[AESEXE] {SERVER MODE}: IP ADDRESS -> " << ip << std::endl;
        std::cout << "[AESEXE] {SERVER MODE}: PORT -> " << real_port << std::endl;
    }

    /*Listen connections*/
    listen(sockfd, 1000);

    while (1) {
      /*
        This loop that retend the connections
       */
        SSL *ssl;
        web_sock = accept(sockfd, (struct sockaddr *)&address, &address_leng);

        // SSL
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl,web_sock);
    }
}

