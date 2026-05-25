#include "../include/Server.hpp"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <ostream>
#include <sys/socket.h>
#include <thread>

int Server::connectManager(SSL *ssl) {
  
    std::cout << "[AESEXE] {SERVER MODE}: new thread for a client has created" << std::endl;

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "Handsheke error" << std::endl;
        ERR_print_errors_fp(stderr);
    } else {
        //initial size buffer define
        size_t tam = 1024;
        size_t total_read = 0;
        char *buffer = (char *)malloc(tam);

        //manager memory error
        if (buffer == NULL) return 1;
        int read_bytes;
        /*
          reallocation memory size system
          this code part has create to case of
          size message is mayor that 1024 bytes

          if is necesary this system incrememt
          exponetly form the size in the heap memory
          with realloc()
         */
        while ((read_bytes = SSL_read(ssl, buffer + total_read, tam - total_read - 1)) > 0) {
            //incrememt in read bytes size
            total_read += read_bytes;

            // comprobation of size buffer
            if (total_read >= tam - 1) {
                tam *= 2; // exponential new size
                char *temp = (char *)realloc(buffer,tam);

                if (temp == NULL) {
                    free(buffer);
                    return 1;
                }
                buffer = temp;
            }
            buffer[total_read] = '\0';
            // exit for while
            if (strstr(buffer,"\r\n\r\n")) break;
        }

        // http respose
        const char *build = "[AESEXE] {SERVER MODE}: ***message received***";
        char respose[512];
        snprintf(respose, sizeof(respose),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 strlen(build), build);
        SSL_write(ssl, respose, strlen(respose));
        free(buffer);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return 0;
}

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
}

void Server::openConnect() {
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
        SSL_set_fd(ssl, web_sock);
        std::thread new_thread(&Server::connectManager, this, ssl);
        new_thread.detach();
    }
  
}

