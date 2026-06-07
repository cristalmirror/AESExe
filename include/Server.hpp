#pragma once
#include "ICipher.hpp"
#include "../include/AES.hpp"
#include "../include/AES256.hpp"
#include "../include/AES192.hpp"
#include "../include/AES128.hpp"
#include "../include/chacha20.hpp"
#include "StreamProcessor.hpp"
#include <iostream>
#include <cstdint>
#include <memory>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <filesystem>
#include <fstream>
#include "Keys.hpp"
#include "loadKey.hpp"
class Server {
protected:
    int sockfd, web_sock, count_thread = 0;
    struct sockaddr_in address, local_address;
    int addrlen = sizeof(address);
    uint16_t port;
    SSL_CTX *ctx;
    socklen_t address_leng;
    int connectManager(SSL *ssl);
    void handleEncrypt(SSL *ssl, const std::string &body);
    void handleDecrypt(SSL *ssl, const std::string &body);
    void handleOpertions(SSL *ssl);

    std::string parseHttpPath(const std::string &rqst);
    std::string parseHttpBody(const std::string &rqst);
    std::string base64Encode(const std::vector<uint8_t> &data);
    std::vector<uint8_t> base64Decode(const std::string &data_encode);
    void sendResponse(SSL *ssl, int status, const std::string &contentType,
                      const std::string &body);
    void sendBinaryRespose(SSL *ssl , const std::vector<uint8_t> &data);
    StreamProcessor cipher;
public:
  
    Server(std::string ip, std::string s_port);
    void initServer();
    void openConnect();
};
