#ifndef CRYPTO_H
#define CRYPTO_H

#include <iostream>
#include <cstring>
#include <thread>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <cstring> 
#include <iomanip>
using namespace std;


#define BUFFER_KEY_SIZE 2048 // Increased for RSA-encrypted key

// Utility to handle OpenSSL errors
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

RSA* loadServerPrivateKey(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        cerr << "Unable to open private key file" << endl;
        exit(1);
    }
    RSA* rsa = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!rsa) handleErrors();
    return rsa;
}

RSA* loadServerPublicKey(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        cerr << "Unable to open public key file" << endl;
        exit(1);
    }
    RSA* rsa = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!rsa) handleErrors();
    return rsa;
}

string sha256(const unsigned char* message, size_t length) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, length);
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}



// Encrypt message using AES-256-ECB
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr)) handleErrors();
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Decrypt message using AES-256-ECB
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr)) 
    {
        std::cerr << "EVP_DecryptInit_ex failed" << std::endl;
        handleErrors();
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        std::cerr << "EVP_DecryptUpdate failed" << std::endl;
        handleErrors();
    }
    plaintext_len = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
    {
        std::cerr << "EVP_DecryptFinal_ex failed" << std::endl;
        handleErrors();
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Generate RSA key pair
RSA* generateRSAKeys() {
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4); // Public exponent 65537
    if (!RSA_generate_key_ex(rsa, 2048, bne, nullptr)) handleErrors();
    BN_free(bne);
    return rsa;
}


#endif