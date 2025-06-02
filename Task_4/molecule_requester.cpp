#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <cstdlib>

#define BUFFER_SIZE 1024

int main(int argc, char* argv[]) {
    const char* server_host = nullptr;
    int tcp_port = -1;
    int udp_port = -1;
    std::string transport;

    static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"tcp-port", required_argument, 0, 'T'},
        {"udp-port", required_argument, 0, 'U'},
        {0, 0, 0, 0}
    };

    // Parse command-line arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "h:T:U:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                server_host = optarg;
                break;
            case 'T':
                tcp_port = std::atoi(optarg);
                transport = "tcp";
                break;
            case 'U':
                udp_port = std::atoi(optarg);
                transport = "udp";
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -h <host> -T <tcp_port> | -U <udp_port>\n";
                return 1;
        }
    }

    // Validation logic
    if (!server_host || (tcp_port == -1 && udp_port == -1)) {
        std::cerr << "Error: Must specify host and one of -T or -U.\n";
        std::cerr << "Usage: " << argv[0] << " -h <host> -T <tcp_port> | -U <udp_port>\n";
        return 1;
    }

    if (tcp_port != -1 && udp_port != -1) {
        std::cerr << "Error: Cannot specify both -T and -U. Choose only one transport.\n";
        return 1;
    }

    int port = (tcp_port != -1) ? tcp_port : udp_port;

    // if (!server_host || port == -1 || (transport != "tcp" && transport != "udp")) {
    //     std::cerr << "Error: Missing or invalid arguments.\n";
    //     std::cerr << "Usage: " << argv[0] << " -h <host> -p <port> [-t tcp|udp]\n";
    //     return 1;
    // }

    // Prepare address lookup
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = (transport == "tcp") ? SOCK_STREAM : SOCK_DGRAM;

    std::string port_str = std::to_string(port);
    int status = getaddrinfo(server_host, port_str.c_str(), &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(status) << "\n";
        return 1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("Socket creation failed");
        freeaddrinfo(res);
        return 1;
    }

    if (transport == "tcp") {
        // TCP: connect to server
        if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            perror("Connection failed");
            freeaddrinfo(res);
            close(sock);
            return 1;
        }

        std::cout << "Connected to molecule_supplier at " << server_host << ":" << port << " via TCP\n";
    } else {
        std::cout << "Ready to send UDP messages to " << server_host << ":" << port << "\n";
    }

    // Main loop for sending commands
    while (true) 
    {
        std::string input;
        std::cout << "Enter command: ";
        std::getline(std::cin, input);

        if (input.empty()) break;

        if (transport == "tcp") {
            send(sock, input.c_str(), input.size(), 0);

            char buffer[BUFFER_SIZE] = {0};
            int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
            if (bytes <= 0) {
                std::cerr << "Connection closed or error.\n";
                break;
            }

            std::cout << "Server response:\n" << buffer << "\n";
        } 
        else // UDP
        {
            
            sendto(sock, input.c_str(), input.size(), 0, res->ai_addr, res->ai_addrlen);

            char buffer[BUFFER_SIZE] = {0};
            struct sockaddr_storage server_reply_addr;
            socklen_t reply_len = sizeof(server_reply_addr);

            int bytes = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0,
                                 (struct sockaddr*)&server_reply_addr, &reply_len);
            if (bytes < 0) {
                perror("recvfrom failed");
                break;
            }

            std::cout << "Server response:\n" << buffer << "\n";
        }
    }

    freeaddrinfo(res);
    close(sock);
    return 0;
}
