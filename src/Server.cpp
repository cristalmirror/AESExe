#include "../include/StreamProcessor.hpp"
#include "../include/AES.hpp"
#include "../include/AES256.hpp"
#include "../include/AES192.hpp"
#include "../include/AES128.hpp"
#include "../include/chacha20.hpp"
#include "../include/Server.hpp"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <ostream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
/*
    json type simplification:
    json is necesary to manager
    the json messages of the clients

*/
using json = nlohmann::json;
namespace fs = std::filesystem;
static const std::string STORE_DIR = "store";
static const std::string CORS =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n";

std::string Server::parseHttpPath(const std::string &req) {
    size_t s = req.find(' ');

    if (s == std::string::npos) return "";
    size_t e = req.find(' ', s + 1);

    if (e == std::string::npos) return "";
    return req.substr(s + 1, e - s -1);
}

std::string Server::parseHttpBody(const std::string &req) {
    size_t sep = req.find("\r\n\r\n");

    if (sep == std::string::npos) return "";
    return req.substr(sep + 4);
}

/*OpenSSL BIO to base64*/
std::string Server::base64Encode(const std::vector<uint8_t> &data) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    char *ptr;
    long len = BIO_get_mem_data(mem, &ptr);
    std::string result(ptr, len);
    BIO_free_all(b64);
    return result;
}

std::vector<uint8_t> Server::base64Decode(const std::string &data_encode) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(data_encode.data(), data_encode.size());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    std::vector<uint8_t> result(data_encode.size());
    int len = BIO_read(b64, result.data(), result.size());
    BIO_free_all(b64);
    if (len > 0) {
        result.resize(len);
    } else {
        result.clear();
    }
    return result;
}

void Server::sendResponse(SSL *ssl, int status, const std::string &ct, const std::string &body) {
    std::string sl = (status == 200)   ? "200 ok"
        : (status == 400) ? "400 Bad Request"
        : (status == 404) ? "404 Not Found"
        : "500 Internal Server Error";

    std::string resp = "HTTP/1.1 " + sl + "\r\n" + CORS +
                       "Content-Type: " + ct + "\r\n" +
                       "Content-Length: " + std::to_string(body.size()) +
                       "\r\n" + "Connection: close\r\n\r\n" + body;
    SSL_write(ssl, resp.c_str(), resp.size());
}

void Server::sendBinaryRespose(SSL *ssl, const std::vector<uint8_t> &data) {
    std::string headers = "HTTP/1.1 200 OK\r\n" + CORS +
                          "Content-Type: application/octet-stream\r\n" +
                          "Content-Length: " + std::to_string(data.size()) +
                          "\r\n" + "Connection: close\r\n\r\n";
    SSL_write(ssl, headers.c_str(), headers.size());
    SSL_write(ssl, reinterpret_cast<const char*>(data.data()), data.size());
}


static bool validCuil(const std::string &cuil) {
    return !cuil.empty() && cuil.size() <= 20 && cuil.find_last_not_of("0123456789-") == std::string::npos;
}

/* ---Handle Operations--- */
void Server::handleOperations(SSL *ssl) {
    std::string resp = "HTTP 1.1 204 No Content \r\n" + CORS +
      "Content-Length: 0\r\nConnection: close\r\n\r\n";
    SSL_write(ssl, resp.c_str(), resp.size());
}

/*operation to handle encrypt*/
void Server::handleEncrypt(SSL *ssl, const std::string &body) {
    json req;
    /*
      the body resept in this code will be
      refactor to json on other data type
      that C++ understand
    */
    try {
        req =json::parse(body);
    } catch (...) {/*if isn't json code send error*/
        sendResponse(ssl, 400, "text/plainm", "Invalid JSON");
        return;
    }

    std::string cuil = req.value("cuil","");
    std::string data = req.value("data", "");
    std::string algo = req.value("algo","");
        
    if (!validCuil(cuil) || data.empty()) {
        sendResponse(ssl, 400, "text/planin", "Missing CUIL or data");
        return;
    }

    /*generations key*/
    std::vector<uint8_t> raw_key = Keys::generate(algo);

    std::istringstream in(data);
    std::ostringstream out;

    if (algo == "aes256") {
        AES256 aes(raw_key);
        StreamProcessor::process(aes, in, out, true);
    } else if (algo == "aes192") {
        AES192 aes(raw_key);
        StreamProcessor::process(aes, in, out, true);
    } else if (algo == "aes128") {
        AES128 aes(raw_key);
        StreamProcessor::process(aes, in, out, true);
    } else if (algo == "chacha20") {
        ChaCha20 cc20(raw_key);
        StreamProcessor::process(cc20, in, out, true);
    }

    // Save in store/cuil.aes
    fs::create_directories(STORE_DIR);
    std::ofstream file(STORE_DIR + "/" + cuil + ".aes", std::ios::binary);
    if (!file) {
        sendResponse(ssl, 500, "text/plain", "Storage error");
        return;
    }    
    std::string ct = out.str();
    file.write(ct.data(), ct.size());
    file.close();
    std::cout << "[AESEXE] /encrypt OK - CUIL" << cuil << std::endl;
    //Devolution of the key (download in client)
    sendBinaryRespose(ssl, raw_key);
}

void Server::handleDecrypt(SSL *ssl, const std::string &body) {
    json req;

    try {
        req = json::parse(body);
    } catch (...) {
        sendResponse(ssl, 400, "text/plain", "Invalid JSON");
        return;
    }

    std::string cuil = req.value("cuil", "");
    std::string algo = req.value("algo", "");

    // La clave viene en base64 desde el cliente
    std::string key_b64 = req.value("key", "");

    if (!validCuil(cuil) || key_b64.empty() || algo.empty()) {
        sendResponse(ssl, 400, "text/plain", "Missing CUIL, key or algo");
        return;
    }

    // Leer el archivo cifrado desde store/
    std::string filepath = STORE_DIR + "/" + cuil + ".aes";
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        sendResponse(ssl, 404, "text/plain", "No encrypted file found for this CUIL");
        return;
    }

    std::ostringstream file_buf;
    file_buf << file.rdbuf();
    file.close();
    std::string encrypted_data = file_buf.str();

    // Decodificar la clave desde base64
    std::vector<uint8_t> raw_key = base64Decode(key_b64);

    /* Reconstruir la clave (se deveria hacer desde la clase loadKey)
        Keys key(algo, raw_key);
    */
    std::istringstream in(encrypted_data);
    std::ostringstream out;

    try {
        if (algo == "aes256") {
            AES256 aes(raw_key);
            StreamProcessor::process(aes, in, out, false);
        } else if (algo == "aes192") {
            AES192 aes(raw_key);
            StreamProcessor::process(aes, in, out, false);
        } else if (algo == "aes128") {
            AES128 aes(raw_key);
            StreamProcessor::process(aes, in, out, false);
        } else if (algo == "chacha20") {
            ChaCha20 cc20(raw_key);
            StreamProcessor::process(cc20, in, out, false);
        } else {
            sendResponse(ssl, 400, "text/plain", "Unknown algorithm");
            return;
        }
    } catch (...) {
        sendResponse(ssl, 500, "text/plain", "Decryption error");
        return;
    }

    std::string plaintext = out.str();

    std::cout << "[AESEXE] /decrypt OK - CUIL: " << cuil << std::endl;

    // Devolver el texto plano al cliente
    sendResponse(ssl, 200, "text/plain", plaintext);
}

int Server::connectManager(SSL *ssl) {
  
    std::cout << "[AESEXE] {SERVER MODE}: new thread for a client has created" << std::endl;

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "Handshake error" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return 1;
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

        
        std::string request(buffer,total_read);
        free(buffer);

        std::string method = request.substr(0, request.find(' '));
        std::string path = parseHttpPath(request);
        std::string body = parseHttpBody(request);

        if (method == "OPTIONS") {
            handleOperations(ssl);
        } else if (method == "POST" && path == "/encrypt") {
            handleEncrypt(ssl, body);
        } else if (method == "POST" && path == "/decrypt") {
            handleDecrypt(ssl,body);
        } else {
            sendResponse(ssl, 400,"text/plain", "Unknow endpoint");
        }
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

    //make the sertificates
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Error: clave privada no coincide con el certificado" << std::endl;
        exit(EXIT_FAILURE);
    }

    
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

