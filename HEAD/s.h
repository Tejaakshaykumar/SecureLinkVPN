#ifndef S_H
#define S_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <openssl/sha.h>
#include <string>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include "crypto.h"
#include <random>

#define FILE_PATH "DB/users.txt"
#define BUFFER_KEY_SIZE 2048

enum Status { ACTIVE, BUSY, INACTIVE };

struct ClientInfo {
    int sock_fd;
    std::string name;
    std::string session_with;
    Status status;
};

extern std::map<int, ClientInfo> clients;
extern std::map<std::string, int> name_to_fd;
map<int, RSA*> client_public_keys; 
RSA* server_private_key = nullptr;


void handle_client_public_key(int client_fd) {
    char buffer[2048] = {0};
    
    int len = recv(client_fd, buffer, 2048, 0);
    if (len <= 0) return;
    
    BIO* bio = BIO_new_mem_buf(buffer, len);
    RSA* client_pub_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!client_pub_key) handleErrors();
    
    client_public_keys[client_fd] = client_pub_key;
}

int decrypt_read(int client_fd, char* decrypted) {
    char buffer[2048] = {0};
    
    int len = read(client_fd, buffer, 2048);
    if (len <= 0) return len; 
    
    int decrypted_len = RSA_private_decrypt(len,
                                          (unsigned char*)buffer,
                                          (unsigned char*)decrypted,
                                          server_private_key,
                                          RSA_PKCS1_PADDING);
    if (decrypted_len == -1) handleErrors();
    
    return decrypted_len;  
}

void send_encrypt(int client_fd, string response) {
    unsigned char encrypted[2048] = {0};
    
    int encrypted_len = RSA_public_encrypt(response.length(),
                                         (unsigned char*)response.c_str(),
                                         encrypted,
                                         client_public_keys[client_fd],
                                         RSA_PKCS1_PADDING);
    if (encrypted_len == -1) handleErrors();
    
    send(client_fd, encrypted, encrypted_len, 0);
}

std::string generate_salt() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(33, 126); 

    std::string salt;
    for (int i = 0; i < 16; i++) {
        salt += static_cast<char>(dis(gen));
    }
    return salt;
}
std::string hash_password(const std::string &password, const std::string &salt) {
    std::string salted_password = salt + password;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)salted_password.c_str(), salted_password.length(), hash);

    std::ostringstream hex_stream;
    for (unsigned char i : hash) {
        hex_stream << std::hex << (int)i;
    }

    return salt + "|RAV|" + hex_stream.str();
}

bool verify_password(const std::string &stored_value, const std::string &password) {
    size_t pos = stored_value.find("|RAV|");
    if (pos == std::string::npos) return false;

    std::string salt = stored_value.substr(0, pos);
    std::string stored_hash = stored_value.substr(pos + 5);

    return hash_password(password, salt).substr(pos + 5) == stored_hash;
}

bool save_credentials(const std::string &username, const std::string &password) {
    std::ifstream file(FILE_PATH);
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string stored_user, stored_hash;
        if (std::getline(iss, stored_user, ':') && stored_user == username) {
            return false;
        }
    }

    file.close();

    std::ofstream outfile(FILE_PATH, std::ios::app);
    outfile << username << ":" << hash_password(password, generate_salt()) << "\n";
    outfile.close();
    
    return true;
}

bool check_credentials(const std::string &username, const std::string &password) {
    std::ifstream file(FILE_PATH);
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string stored_user, stored_hash;
        if (std::getline(iss, stored_user, ':') && std::getline(iss, stored_hash) && stored_user == username) {
            return verify_password(stored_hash, password);
        }
    }

    return false;
}


bool handle_client(int client_socket) {
    char decrypted[2048] = {0};
    int decrypted_len = decrypt_read(client_socket, decrypted);
    if (decrypted_len > 0) {
        decrypted[decrypted_len] = '\0';
    }
    std::string request(decrypted);

    std::istringstream iss(request);
    std::string command, username, password;
    iss >> command >> username >> password;

    std::string response;
    if (command == "signup") {
        response = save_credentials(username, password) ? "Signup successful" : "Username already exists";
    } else if (command == "login") {
        response = check_credentials(username, password) ? "Login successful" : "Invalid username or password";
    } else {
        response = "Invalid command";
    }
    send_encrypt(client_socket, response);
     return response == "Login successful";
}

void send_client_list(int client_fd) {
    std::stringstream list;
    list << "CLIENT_LIST:";
    for (const auto& [fd, info] : clients) {
        if (info.status != INACTIVE && fd != client_fd) {
            list << info.name << "," << (info.status == ACTIVE ? "active" : "busy") << ";";
        }
    }
    std::string list_str = list.str();
    // if (list_str.length() > 12) {
        send_encrypt(client_fd, list_str);

    // } else {
    //     std::string response ="No other active clients available.";
    //     send_encrypt(client_fd, response);
    // }
}

void AES_SESSION_KEY(int client_fd, int requester_fd) {
    char buffer[BUFFER_KEY_SIZE];    
        int pub_key_len;
        read(client_fd, &pub_key_len, sizeof(pub_key_len));
        char* pub_key = new char[pub_key_len];
        read(client_fd, pub_key, pub_key_len);
        
        int pub_key_len1;
        read(requester_fd, &pub_key_len1, sizeof(pub_key_len1));
        char* pub_key1 = new char[pub_key_len1];
        read(requester_fd, pub_key1, pub_key_len1);

        BIO* bio = BIO_new_mem_buf(pub_key, pub_key_len);
        RSA* rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
        BIO* bio1 = BIO_new_mem_buf(pub_key1, pub_key_len1);
        RSA* rsa1 = PEM_read_bio_RSAPublicKey(bio1, nullptr, nullptr, nullptr);


    unsigned char aes_key[32]; // 256 bits
    RAND_bytes(aes_key, 32);
    unsigned char encrypted_key[BUFFER_KEY_SIZE];
    int encrypted_key_len = RSA_public_encrypt(32, aes_key, encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_key_len == -1) handleErrors();
    
    unsigned char encrypted_key1[BUFFER_KEY_SIZE];
    int encrypted_key_len1 = RSA_public_encrypt(32, aes_key, encrypted_key1, rsa1, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_key_len1 == -1) handleErrors();

    send(client_fd, &encrypted_key_len, sizeof(encrypted_key_len), 0);
    send(client_fd, encrypted_key, encrypted_key_len, 0);

    send(requester_fd, &encrypted_key_len1, sizeof(encrypted_key_len1), 0);
    send(requester_fd, encrypted_key1, encrypted_key_len1, 0);

    RSA_free(rsa);
    RSA_free(rsa1);
    BIO_free(bio);
    BIO_free(bio1);
    delete[] pub_key;
    delete[] pub_key1;
}
void process_client_message(int client_fd, const char* buffer, int bytes_read) {
    std::string message(buffer, bytes_read);
    std::string client_name = clients[client_fd].name;
    // std::cout << "Received from " << client_name << " (FD " << client_fd << "): " << message << std::endl;

    if (message == "USERDIC") {
        send_client_list(client_fd);
    } else if (message == "EXIT") {
        std::string session_partner = clients[client_fd].session_with;
        if (!session_partner.empty()) {
            int partner_fd = name_to_fd[session_partner];
            if (clients.count(partner_fd) && clients[partner_fd].status != INACTIVE) {
                clients[partner_fd].status = ACTIVE;
                clients[partner_fd].session_with = "";
                std::string response = "SESSION_END";
                send_encrypt(client_fd, response);
            }
        }
        clients[client_fd].status = INACTIVE;
        close(client_fd);
        name_to_fd.erase(client_name);
        clients.erase(client_fd);
    } else if (message.substr(0, 7) == "CONNECT") {
        std::string target = message.substr(8);
        if (name_to_fd.count(target) && clients[name_to_fd[target]].status == ACTIVE) {
            int target_fd = name_to_fd[target];
            std::string response = "REQUEST:" + client_name;
            send_encrypt(target_fd, response);

        } else {
            std::string response = "Target not available.";
            send_encrypt(client_fd, response);

        }
    } else if (message.substr(0, 6) == "ACCEPT") {

        std::string requester = message.substr(7);
        if (name_to_fd.count(requester) && clients[name_to_fd[requester]].status == ACTIVE) {
            int requester_fd = name_to_fd[requester];
            clients[client_fd].status = BUSY;
            clients[client_fd].session_with = requester;
            clients[requester_fd].status = BUSY;
            clients[requester_fd].session_with = client_name;
            std::string response = "SESSION_START";
            send_encrypt(client_fd, response);
            send_encrypt(requester_fd, response);
            std::cout << "Session started between " << client_name << " and " << requester << std::endl;
            
        AES_SESSION_KEY(client_fd,requester_fd);

        }
    }else if (message.substr(0, 6) == "REJECT") {
        std::string requester = message.substr(7,message.size());
            int requester_fd = name_to_fd[requester];
            std::string response = "CONNECTION REJECTED FOR " + requester;
            send_encrypt(requester_fd, response);
            clients[client_fd].session_with = "";
    }
    
    else if (clients[client_fd].status == BUSY) {
        std::string partner = clients[client_fd].session_with;
        int partner_fd = name_to_fd[partner];
        if (clients.count(partner_fd) && clients[partner_fd].status == BUSY) {
            send_encrypt(partner_fd, message);

        }
    }
}

#endif