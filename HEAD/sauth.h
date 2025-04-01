#ifndef SAUTH_H
#define SAUTH_H

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <unistd.h>

void initialize_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    OPENSSL_init_crypto(0, NULL);
}

SSL_CTX* create_server_context() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context\n";
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "certs/server_cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "certs/server_key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void handle_client(SSL* ssl) {
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }


    const char* msg = "Hello from Secure Server!";
    SSL_write(ssl, msg, strlen(msg));

}



#endif