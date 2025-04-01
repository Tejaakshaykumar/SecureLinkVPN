
// #include <iostream>
// #include <arpa/inet.h>
// #include <netinet/in.h>
// #include <sys/socket.h>
// #include <sys/poll.h>
// #include <cstring>
// #include <unistd.h>
// #include <sstream>
// #include <netdb.h> // For getaddrinfo()

// #define SERVER_HOST "0.tcp.in.ngrok.io" // Ngrok hostname
// #define SERVER_PORT "13321"            // Ngrok port as string
// #define BUFFER_SIZE 4096

// int sock_fd;
// std::string username;
// bool in_session = false;
// std::string session_with;

// void process_server_message(const char* buffer, int bytes_read) {
//     std::string message(buffer, bytes_read);
//     if (message.substr(0, 11) == "CLIENT_LIST") {
//         std::cout << "\nAvailable clients:\n";
//         std::stringstream ss(message.substr(12));
//         std::string item;
//         while (std::getline(ss, item, ';')) {
//             if (!item.empty()) {
//                 std::string name = item.substr(0, item.find(','));
//                 std::string status = item.substr(item.find(',') + 1);
//                 std::cout << name << " (" << status << ")" << std::endl;
//             }
//         }
//         std::cout << "Enter command: ";
//     } else if (message.substr(0, 7) == "REQUEST") {
//         session_with = message.substr(8);
//         std::cout << "\nConnection request from " << session_with 
//                   << ". Accept? (y/n): ";
//         std::string response;
//         std::getline(std::cin, response);
//         if (response == "y") {
//             write(sock_fd, ("ACCEPT:" + session_with).c_str(), 7 + session_with.length());
//         }
//     } else if (message == "SESSION_START") {
//         in_session = true;
//         std::cout << "\nSession started with " << session_with << "\n";
//     } else if (message == "SESSION_END") {
//         in_session = false;
//         session_with = "";
//         std::cout << "\nSession ended. Enter command: ";
//     } else if (message.substr(0, 4) == "MSG:") {
//         size_t colon1 = message.find(':', 4);
//         if (colon1 != std::string::npos) {
//             std::string sender = message.substr(4, colon1 - 4);
//             std::string msg = message.substr(colon1 + 1);
//             std::cout << "\n" << sender << ": " << msg << "\n";
//         }
//     } else {
//         std::cout << "Server: " << message << "\nEnter command: ";
//     }
//     std::cout.flush();
// }

// int main(int argc, char* argv[]) {
//     if (argc != 2) {
//         std::cerr << "Usage: ./client <username>" << std::endl;
//         return 1;
//     }

//     username = argv[1];

//     // Use getaddrinfo to resolve the hostname
//     struct addrinfo hints, *res;
//     memset(&hints, 0, sizeof(hints));
//     hints.ai_family = AF_INET;     // IPv4
//     hints.ai_socktype = SOCK_STREAM;

//     int status = getaddrinfo(SERVER_HOST, SERVER_PORT, &hints, &res);
//     if (status != 0) {
//         std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
//         return 1;
//     }

//     // Create socket
//     sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
//     if (sock_fd < 0) {
//         perror("Socket creation failed");
//         freeaddrinfo(res);
//         return 1;
//     }

//     // Connect to server
//     if (connect(sock_fd, res->ai_addr, res->ai_addrlen) < 0) {
//         perror("Connection to server failed");
//         close(sock_fd);
//         freeaddrinfo(res);
//         return 1;
//     }
//     freeaddrinfo(res); // Free the addrinfo structure

//     // Send username to server
//     write(sock_fd, username.c_str(), username.length());

//     char buffer[BUFFER_SIZE];
//     int bytes_read = read(sock_fd, buffer, BUFFER_SIZE - 1);
//     if (bytes_read <= 0) {
//         perror("Failed to connect");
//         close(sock_fd);
//         return 1;
//     }
//     buffer[bytes_read] = '\0';
//     std::cout << buffer << std::endl;

//     struct pollfd fds[2];
//     fds[0].fd = STDIN_FILENO; // User input
//     fds[0].events = POLLIN;
//     fds[1].fd = sock_fd;      // Server messages
//     fds[1].events = POLLIN;

//     while (true) {
//         if (poll(fds, 2, -1) < 0) {
//             perror("Poll failed");
//             break;
//         }

//         if (fds[0].revents & POLLIN) {
//             std::string input;
//             std::getline(std::cin, input);
//             if (!input.empty()) {
//                 if (input == "EXIT") {
//                     write(sock_fd, input.c_str(), input.length());
//                     break;
//                 } else if (input == "USERDIC" || input.substr(0, 7) == "CONNECT") {
//                     write(sock_fd, input.c_str(), input.length());
//                 } else if (in_session) {
//                     write(sock_fd, input.c_str(), input.length());
//                 }
//             }
//         }

//         if (fds[1].revents & POLLIN) {
//             char buffer[BUFFER_SIZE] = {0};
//             int bytes_read = read(sock_fd, buffer, BUFFER_SIZE - 1);
//             if (bytes_read <= 0) {
//                 std::cout << "Disconnected from server" << std::endl;
//                 break;
//             }
//             process_server_message(buffer, bytes_read);
//         }
//     }

//     close(sock_fd);
//     return 0;
// }





//###############################################################################################################





// #include <iostream>
// #include <arpa/inet.h>
// #include <netinet/in.h>
// #include <sys/socket.h>
// #include <sys/poll.h>
// #include <cstring>
// #include <unistd.h>
// #include <sstream>
// #include "HEAD/c.h"
// #include "HEAD/cauth.h"
// #include <netdb.h> // For getaddrinfo()

// #define SERVER_HOST "0.tcp.in.ngrok.io" // Ngrok hostname
// #define SERVER_PORT "11398"    
// #define BUFFER_SIZE 4096


// int sock_fd;
// std::string username;
// bool in_session = false;
// std::string session_with;


// int main(int argc, char* argv[]) {
//     initialize_openssl();
//     SSL_CTX* ctx = create_client_context();
//     client_rsa = generateRSAKeys();
//     server_pub_key = loadServerPublicKey("server_public_key.pem");
    
//     if (argc != 2) {
//         std::cerr << "Usage: ./client <username>" << std::endl;
//         return 1;
//     }

//     username = argv[1];

//     struct addrinfo hints, *res;
//     memset(&hints, 0, sizeof(hints));
//     hints.ai_family = AF_INET;     // IPv4
//     hints.ai_socktype = SOCK_STREAM;

//     int status = getaddrinfo(SERVER_HOST, SERVER_PORT, &hints, &res);
//     if (status != 0) {
//         std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
//         return 1;
//     }

//     sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
//     if (sock_fd < 0) {
//         perror("Socket creation failed");
//         freeaddrinfo(res);
//         return 1;
//     }

//     // Connect to server
//     if (connect(sock_fd, res->ai_addr, res->ai_addrlen) < 0) {
//         perror("Connection to server failed");
//         close(sock_fd);
//         freeaddrinfo(res);
//         return 1;
//     }
//     freeaddrinfo(res);

//     SSL* ssl = SSL_new(ctx);
//     SSL_set_fd(ssl, sock_fd);
//     communicate_with_server(ssl);


//     BIO* bio = BIO_new(BIO_s_mem());
//     PEM_write_bio_RSA_PUBKEY(bio, client_rsa);
//     char* key_buffer;
//     long key_len = BIO_get_mem_data(bio, &key_buffer);
//     send(sock_fd, key_buffer, key_len, 0);
//     // BIO_free(bio);

//     bool authenticated = false;

//     while (!authenticated) {
//         std::cout << "1. Signup\n2. Login\n3. Exit\nChoose an option: ";
//         int choice;
//         std::cin >> choice;

//         if (choice == 3) {
//             std::cout << "Exiting...\n";
//             break;
//         }

//         std::string  password, confirm_password;

//         std::cout << "Enter password: ";
//         set_echo(false);
//         std::cin >> password;
//         set_echo(true);
//         std::cout << "\n"; 

//         if (choice == 1) {
//             std::cout << "Confirm password: ";
//             set_echo(false);
//             std::cin >> confirm_password;
//             set_echo(true);
//             std::cout << "\n";

//             if (password != confirm_password) {
//                 std::cout << "Passwords do not match. Please try again.\n";
//                 continue;
//             }

//             std::string response = send_request(sock_fd, "signup", username, password);
//             std::cout << "Server Response: " << response << std::endl;

//             if (response != "Signup successful") {
//                 std::cout << "Signup failed. Please try again.\n";
//             } else {
//                 std::cout << "Signup successful. Please login.\n";
//             }
//         } else if (choice == 2) {
//             std::string response = send_request(sock_fd, "login", username, password);
//             std::cout << "Server Response: " << response << std::endl;

//             if (response == "Login successful") {
//                 authenticated = true;
//                 std::cout << "Welcome, " << username << "!\n";
//             } else {
//                 std::cout << "Login failed. Please try again.\n";
//             }
//         } else {
//             std::cout << "Invalid choice. Please try again.\n";
//         }
//     }

//     write(sock_fd, username.c_str(), username.length());

//     char buffer[BUFFER_SIZE];
//     int bytes_read = read(sock_fd, buffer, BUFFER_SIZE - 1);
//     if (bytes_read <= 0) {
//         perror("Failed to connect");
//         close(sock_fd);
//         return 1;
//     }
//     buffer[bytes_read] = '\0';
//     std::cout << buffer << std::endl;

//     struct pollfd fds[2];
//     fds[0].fd = STDIN_FILENO; 
//     fds[0].events = POLLIN;
//     fds[1].fd = sock_fd;   
//     fds[1].events = POLLIN;

//     while (true) {
//         if (poll(fds, 2, -1) < 0) {
//             perror("Poll failed");
//             break;
//         }

//         if (fds[0].revents & POLLIN) {
//             std::string input;
//             std::getline(std::cin, input);
//             if (!input.empty()) {
//                 if (input == "EXIT") {
//                     write(sock_fd, input.c_str(), input.length());
//                     break;
//                 } else if (input == "USERDIC" || input.substr(0, 7) == "CONNECT") {
//                     write(sock_fd, input.c_str(), input.length());
//                 } else if (in_session) {
//                     encrypt_message(sock_fd,input);
//                     // write(sock_fd, input.c_str(), input.length());
//                 }
//             }
//         }

//         if (fds[1].revents & POLLIN) {
//             char buffer[BUFFER_SIZE] = {0};
//             int bytes_read = read(sock_fd, buffer, BUFFER_SIZE - 1);
//             if (bytes_read <= 0) {
//                 std::cout << "Disconnected from server" << std::endl;
//                 break;
//             }
//             process_server_message(buffer, bytes_read,sock_fd);
//         }
//     }

//     close(sock_fd);
//     SSL_CTX_free(ctx);
//     SSL_shutdown(ssl);
//     SSL_free(ssl);
//     return 0;
// }