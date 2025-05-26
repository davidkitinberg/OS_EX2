#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdlib>
#include <getopt.h>

#define BUFFER_SIZE 1024

int main(int argc, char* argv[]) {

    // Server address is provided as command-line argument (usage)
    const char* server_host = nullptr;
    int port = -1;

    int opt;
    while ((opt = getopt(argc, argv, "h:p:")) != -1) {
        switch (opt) {
            case 'h':
                server_host = optarg;
                break;
            case 'p':
                port = std::atoi(optarg);
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -h <server hostname or IP> -p" << std::endl;
                return 1;
        }
    }

    // Validate usage
    if (server_host == nullptr || port == -1) {
        std::cerr << "Error: Hostname or IP is required.\n";
        std::cerr << "Usage: " << argv[0] << " -h <server hostname or IP> -p" << std::endl;
        return 1;
    }

    // Setup hints for getaddrinfo (IPv4, TCP)
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET; // Force IPv4 only
    hints.ai_socktype = SOCK_STREAM; // TCP socket

    std::string port_str = std::to_string(port);

    // Resolve hostname and port using getaddrinfo
    int status = getaddrinfo(server_host, port_str.c_str(), &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return 1;
    }

    // Create TCP socket
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("Socket creation failed");
        freeaddrinfo(res);
        return 1;
    }

    // Connect to the server
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        perror("Connection failed");
        freeaddrinfo(res);
        close(sock);
        return 1;
    }

    // Free the resolved address info after connect
    freeaddrinfo(res);

    std::cout << "Connected to atom_warehouse at " << server_host << ":" << port << "\n";

    // Main loop to send user input and receive server response
    while (true) 
    {
        std::string input;
        std::cout << "Enter command: ";
        std::getline(std::cin, input);

        // If input from user is empty line (Enter) - exit the main loop
        if (input.empty()) break;

        // Send user input to server
        send(sock, input.c_str(), input.length(), 0);

        // Receive response from server
        char buffer[BUFFER_SIZE] = {0};
        int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes <= 0) {
            std::cerr << "Connection closed or error." << std::endl;
            break;
        }

        // Print server response
        std::cout << "Server response:\n" << buffer << std::endl;
    }

    // Close socket and exit
    close(sock);
    return 0;
}
