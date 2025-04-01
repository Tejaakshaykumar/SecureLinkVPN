#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <cstring>
#include <unistd.h>
#include <map>
#include <sstream>
#include <vector>
#include "HEAD/s.h"
#include "HEAD/sauth.h"

#define SERVER_PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100

std::map<int, ClientInfo> clients; 
std::map<std::string, int> name_to_fd;



int main() {
    initialize_openssl();
    SSL_CTX* ctx = create_server_context();
    server_private_key = loadServerPrivateKey("certs/server_key.pem");

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    std::cout << "Server started, waiting for clients..." << std::endl;

    std::vector<struct pollfd> fds;
    fds.push_back({server_fd, POLLIN, 0});

    while (true) {
        if (poll(fds.data(), fds.size(), -1) < 0) {
            perror("Poll failed");
            continue;
        }

        for (size_t i = 0; i < fds.size(); i++) {
            if (fds[i].revents & POLLIN) {
                if (fds[i].fd == server_fd) {
                    struct sockaddr_in client_addr{};
                    socklen_t client_len = sizeof(client_addr);
                    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
                    if (client_fd < 0) {
                        perror("Accept failed");
                        continue;
                    }

                    SSL* ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, client_fd);
                    handle_client(ssl);

                    // SSL_shutdown(ssl); // Shutdown SSL connection
                    // SSL_free(ssl);

                    handle_client_public_key(client_fd);

                    bool authenticated = false;
                    while(authenticated==false){
                        authenticated=handle_client(client_fd);
                    }
                    char buffer[BUFFER_SIZE] = {0};

                    int bytes_read = decrypt_read(client_fd, buffer);
                    if (bytes_read > 0) {
                        char decrypted[bytes_read] = {0};
                    }
                    // std::cout << buffer << std::endl;


                    std::string client_name(buffer, bytes_read);
                    ClientInfo client_info = {client_fd, client_name, "", ACTIVE};
                    clients[client_fd] = client_info;
                    name_to_fd[client_name] = client_fd;
                    fds.push_back({client_fd, POLLIN, 0});
                    std::string response = "Connected! Enter 'USERDIC', 'CONNECT <name>', or 'EXIT': ";
                    send_encrypt(client_fd, response);

                    std::cout << "Client " << client_name << " connected (FD " << client_fd << ")" << std::endl;
                } else {
                    int client_fd = fds[i].fd;
                    char buffer[BUFFER_SIZE] = {0};
                    int decrypted_len = decrypt_read(client_fd, buffer);
                    if (decrypted_len <= 0) {
                        std::cout << "Client " << clients[client_fd].name << " disconnected" << std::endl;
                        std::string session_partner = clients[client_fd].session_with;
                        if (!session_partner.empty()) {
                            int partner_fd = name_to_fd[session_partner];
                            if (clients.count(partner_fd)) {
                                clients[partner_fd].status = ACTIVE;
                                clients[partner_fd].session_with = "";

                                std::string response = "SESSION_END";
                                send_encrypt(client_fd, response);
                            }
                        }
                        close(client_fd);
                        name_to_fd.erase(clients[client_fd].name);
                        clients.erase(client_fd);
                        fds.erase(fds.begin() + i);
                        i--;
                    } else {
                        // std::cout << buffer << "\n";
                        process_client_message(client_fd, buffer, decrypted_len);
                    }
                }
            }
        }
    }
    close(server_fd);
    SSL_CTX_free(ctx); 
    RSA_free(server_private_key);
    // cleanup_openssl();

    return 0;
}



