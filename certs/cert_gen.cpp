#include <iostream>
#include <cstdlib>

void runCommand(const std::string& command) {
    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "Error executing: " << command << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main() {
    std::cout << "Generating CA private key..." << std::endl;
    runCommand("openssl genrsa -out ca_key.pem 2048");

    std::cout << "Creating self-signed CA certificate..." << std::endl;
    runCommand("openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 365 -out ca_cert.pem \
    -subj \"/C=IN/ST=Telangana/L=Hyderabad/O=MyCA/CN=MyRootCA\"");

    std::cout << "Generating server private key..." << std::endl;
    runCommand("openssl genrsa -out server_key.pem 2048");

    std::cout << "Creating Certificate Signing Request (CSR) for the server..." << std::endl;
    runCommand("openssl req -new -key server_key.pem -out server_csr.pem \
    -subj \"/C=IN/ST=Telangana/L=Hyderabad/O=MyServer/CN=127.0.0.1\"");

    std::cout << "Signing server certificate with CA certificate..." << std::endl;
    runCommand("openssl x509 -req -in server_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial \
    -out server_cert.pem -days 365 -sha256");

    std::cout << "Certificate generation completed successfully!" << std::endl;
    return 0;
}


// RUN:
// g++ cert_gen.cpp
// ./out