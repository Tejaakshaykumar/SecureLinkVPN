#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <cstring>
#include <unistd.h>
#include <sstream>
#include "HEAD/c.h"
#include "HEAD/cauth.h"
#include <netdb.h>

#define SERVER_HOST "0.tcp.in.ngrok.io" // Ngrok hostname
#define SERVER_PORT "19855"         
#define BUFFER_SIZE 4096


int main(int argc, char* argv[]) {
    initialize_openssl();
    SSL_CTX* ctx = create_client_context();
    client_rsa = generateRSAKeys();
    
    if (argc != 2) {
        std::cerr << "Usage: ./client <username>" << std::endl;
        return 1;
    }

    username = argv[1];

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;     // IPv4
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(SERVER_HOST, SERVER_PORT, &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return 1;
    }

    sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        freeaddrinfo(res);
        return 1;
    }

    // Connect to server
    if (connect(sock_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("Connection to server failed");
        close(sock_fd);
        freeaddrinfo(res);
        return 1;
    }
    freeaddrinfo(res);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock_fd);
    communicate_with_server(ssl);

    server_pub_key = loadServerPublicKey("server_public_key.pem");

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, client_rsa);
    char* key_buffer;
    long key_len = BIO_get_mem_data(bio, &key_buffer);
    send(sock_fd, key_buffer, key_len, 0);
    BIO_free(bio);

    bool authenticated = false;

    while (!authenticated) {
        std::cout << "1. Signup\n2. Login\n3. Exit\nChoose an option: ";
        int choice;
        std::cin >> choice;

        if (choice == 3) {
            std::cout << "Exiting...\n";
            break;
        }

        std::string  password, confirm_password;

        std::cout << "Enter password: ";
        set_echo(false);
        std::cin >> password;
        set_echo(true);
        std::cout << "\n"; 

        if (choice == 1) {
            std::cout << "Confirm password: ";
            set_echo(false);
            std::cin >> confirm_password;
            set_echo(true);
            std::cout << "\n";

            if (password != confirm_password) {
                std::cout << "Passwords do not match. Please try again.\n";
                continue;
            }

            std::string response = send_request(sock_fd, "signup", username, password);

            if (response != "Signup successful") {
                std::cout << "Signup failed. Please try again.\n";
            } else {
                std::cout << "Signup successful. Please login.\n";
            }
        } else if (choice == 2) {
            std::string response = send_request(sock_fd, "login", username, password);

            if (response == "Login successful") {
                authenticated = true;
                std::cout << "Welcome, " << username << "!\n";
            } else {
                std::cout << "Login failed. Please try again.\n";
            }
        } else {
            std::cout << "Invalid choice. Please try again.\n";
        }
    }
    send_encrypt(sock_fd, username);

    unsigned char buffer[BUFFER_SIZE] ={0};

    int decrypted_len = read_decrypt(sock_fd, buffer);
    if (decrypted_len > 0) {
        buffer[decrypted_len] = '\0';
    }
    buffer[decrypted_len] = '\0';
    std::cout << buffer << std::endl;

    struct pollfd fds[2];
    fds[0].fd = STDIN_FILENO; 
    fds[0].events = POLLIN;
    fds[1].fd = sock_fd;   
    fds[1].events = POLLIN;

    while (true) {
        if (poll(fds, 2, -1) < 0) {
            perror("Poll failed");
            break;
        }

        if (fds[0].revents & POLLIN) {
            std::string input;
            std::getline(std::cin, input);
            if (!input.empty()) {
                if (input == "EXIT") {
                    send_encrypt(sock_fd, input);

                    break;
                } else if (input == "USERDIC") {
                    send_encrypt(sock_fd, input);

                }else if (input.substr(0, 7) == "CONNECT") {
                    session_with=input.substr(8, input.size());
                    std::cout << "Connect REQUEST SENT to " << session_with << std::endl;
                    send_encrypt(sock_fd, input);

                } else if (in_session) {
                    encrypt_message(sock_fd,input);
                }
            }
        }

        if (fds[1].revents & POLLIN) {
            unsigned char buffer[BUFFER_SIZE] = {0};
            int decrypted_len = read_decrypt(sock_fd, buffer);
            if (decrypted_len > 0) {
                buffer[decrypted_len] = '\0';
            }
            process_server_message(reinterpret_cast<char*>(buffer), decrypted_len,sock_fd);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock_fd);
    SSL_CTX_free(ctx);
    RSA_free(client_rsa);
    RSA_free(server_pub_key);
    // cleanup_openssl();
    return 0;
}

