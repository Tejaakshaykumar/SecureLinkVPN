#ifndef CAUTH_H
#define CAUTH_H

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

void print_public_key(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char* key_buffer;
    long key_length = BIO_get_mem_data(bio, &key_buffer);
        FILE* keyFile = fopen("server_public_key.pem", "w");
        if (!keyFile) {
            perror("Error opening server_public_key.pem for writing");
            BIO_free(bio);
            return;
        }
        PEM_write_PUBKEY(keyFile, pkey);
        fclose(keyFile);
    BIO_free(bio);
}


void communicate_with_server(SSL* ssl) {
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    std::cout << "Connected and verified server successfully!\n";

    X509* server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert) {
        EVP_PKEY* server_pubkey = X509_get_pubkey(server_cert);
        if (server_pubkey) {
            print_public_key(server_pubkey);
            EVP_PKEY_free(server_pubkey);
        }
        X509_free(server_cert);
    } else {
        std::cerr << "Failed to get server certificate!\n";
    }

    char buffer[1024] = {0};
    SSL_read(ssl, buffer, sizeof(buffer));

}

SSL_CTX* create_client_context() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context\n";
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "certs/ca_cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}


#endif