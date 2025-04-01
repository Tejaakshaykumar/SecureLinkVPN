#ifndef C_H
#define C_H

#include <iostream>
#include <cstring>
#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <unistd.h>
#include <termios.h>
#include "crypto.h"
#include "cauth.h"
#define PORT 8080

int sock_fd;
std::string username;
bool in_session = false;
std::string session_with;
RSA* server_pub_key=nullptr;
RSA* client_rsa=nullptr;

#define BUFFER_KEY_SIZE 2048 

unsigned char aes_key[32]; 

void set_echo(bool enable) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (enable) {
        tty.c_lflag |= ECHO;
    } else {
        tty.c_lflag &= ~ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

void send_encrypt(int sock_fd, const std::string& message) {
    unsigned char encrypted[2048] = {0};
    int encrypted_len = RSA_public_encrypt(message.length(), (unsigned char*)message.c_str(), encrypted, server_pub_key, RSA_PKCS1_PADDING);
    if (encrypted_len == -1) handleErrors();
    send(sock_fd, encrypted, encrypted_len, 0);
}

int read_decrypt(int sock_fd, unsigned char* decrypted) {
    char buffer[2048] = {0};
    int len = recv(sock_fd, buffer, 2048, 0);
    if (len <= 0) return -1; 
    int decrypted_len = RSA_private_decrypt(len, (unsigned char*)buffer, decrypted, client_rsa, RSA_PKCS1_PADDING);
    if (decrypted_len == -1) handleErrors();
    return decrypted_len;
}


void encrypt_message(int sock_fd, const std::string &message) {
    int ciphertext_len = message.size() + AES_BLOCK_SIZE;
    unsigned char* ciphertext = new unsigned char[ciphertext_len];
    unsigned char* plaintext = new unsigned char[message.size()];
    memcpy(plaintext, message.c_str(), message.size());

    unsigned char iv[16];
    ciphertext_len = encrypt(plaintext, message.size(), aes_key, iv, ciphertext);
    std::string hash_value = sha256(reinterpret_cast<const unsigned char*>(ciphertext), ciphertext_len);
    std::string final_message = string(reinterpret_cast<const char*>(ciphertext), ciphertext_len) + "|VAR|" + hash_value;
    send_encrypt(sock_fd, final_message);
    delete[] ciphertext;
    delete[] plaintext;

}

std::string send_request(int sock_fd, const std::string &command, const std::string &username, const std::string &password) {
    std::string message = command + " " + username + " " + password;
    send_encrypt(sock_fd, message);
    unsigned char decrypted[2048] = {0};
    int decrypted_len = read_decrypt(sock_fd, decrypted);
    if (decrypted_len > 0) {
        decrypted[decrypted_len] = '\0';
    }

    return std::string(reinterpret_cast<char*>(decrypted));

}

void AES_SESSION_KEY(int sock_fd){
    RSA* rsa = generateRSAKeys();
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);
    int pub_key_len = BIO_pending(bio);
    char* pub_key = new char[pub_key_len];
    BIO_read(bio, pub_key, pub_key_len);
    send(sock_fd, &pub_key_len, sizeof(pub_key_len), 0);
    send(sock_fd, pub_key, pub_key_len, 0);

    int valread;
    char buffer1[BUFFER_KEY_SIZE] = {0};

    int encrypted_key_len;
    valread = read(sock_fd, &encrypted_key_len, sizeof(encrypted_key_len));
    valread = read(sock_fd, buffer1, encrypted_key_len);

    int decrypted_len = RSA_private_decrypt(encrypted_key_len, (unsigned char*)buffer1, aes_key, rsa, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_len != 32){
        std::cerr << "Decryption failed. Length: " << decrypted_len << std::endl;
        handleErrors();
        return;
    }
    RSA_free(rsa);
    BIO_free(bio);
    delete[] pub_key;
}

void decrypt_message(int sock_fd,std::string message) {

    size_t pos = message.find("|VAR|");
    if (pos == string::npos) {
        std::cerr << "Invalid message format!" << std::endl;
        return ;
    }
    std::string ciphertext_str = message.substr(0, pos);
    std::string received_hash = message.substr(pos + 5);
    unsigned char* ciphertext = new unsigned char[ciphertext_str.size()];
    memcpy(ciphertext, ciphertext_str.c_str(), ciphertext_str.size());
    std::string computed_hash = sha256(ciphertext,ciphertext_str.size());
    if (computed_hash == received_hash) {
        int plaintext_len = ciphertext_str.size(); // Initial estimate
        unsigned char* plaintext = new unsigned char[plaintext_len + 1]; // +1 for null terminator

    unsigned char* iv;

        plaintext_len = decrypt(ciphertext, ciphertext_str.size(), aes_key, iv, plaintext);
        if (plaintext_len >= 0) {
            plaintext[plaintext_len] = '\0'; // Null-terminate
            std::cout << session_with << ": " << plaintext << std::endl;
        } else {
            std::cerr << "Decryption failed!" << std::endl;
        }
        delete[] plaintext;
    } else {
        std::cout << "Integrity check failed!" << std::endl;
    }

    delete[] ciphertext;   
}

void process_server_message(const char* buffer, int bytes_read,int sock_fd) {
    std::string message(buffer, bytes_read);

    if (message.substr(0, 11) == "CLIENT_LIST") {
        std::cout << "\nAvailable clients:\n";
        std::stringstream ss(message.substr(12));
        std::string item;
        while (std::getline(ss, item, ';')) {
            if (!item.empty()) {
                std::string name = item.substr(0, item.find(','));
                std::string status = item.substr(item.find(',') + 1);
                std::cout << name << " (" << status << ")" << std::endl;
            }
        }
        std::cout << "Enter command: ";
    } else if (message.substr(0, 7) == "REQUEST") {
        session_with = message.substr(8);
        std::cout << "\nConnection request from " << session_with << ". Accept? (y/n): ";
        std::string response;
        std::getline(std::cin, response);
        cin>>response;
        if (response == "y") {
            std::string input="ACCEPT:" + session_with;
            send_encrypt(sock_fd, input);

        }else{
            std::string input="REJECT:" + session_with;
            send_encrypt(sock_fd, input);
            session_with = "";
        }
    } else if (message == "SESSION_START") {
        in_session = true;
        std::cout << "\nSession started with " << session_with << "\n";

        AES_SESSION_KEY(sock_fd);

    } else if (message.substr(0, 10) == "CONNECTION") {
        std::cout <<  message << "\n";

     }

    else if (in_session) {
        decrypt_message(sock_fd,message);
    }else if (message == "SESSION_END") {
    }
    else {
        std::cout << "\nInvalid command or not in a session.\n";
        std::cout << "\nEnter command: ";
    }
    std::cout.flush();
}

#endif