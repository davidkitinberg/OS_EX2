#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <getopt.h>
#include <cstdlib>
#include <fcntl.h>

#define BUFFER_SIZE 1024

int main(int argc, char* argv[]) {
    const char* server_host = nullptr; // Hostname or IP address of the server (for TCP/UDP)
    int tcp_port = -1; // TCP port number
    int udp_port = -1; // UDP port number
    std::string uds_stream_path; // Path to the Unix Domain Socket stream file
    std::string uds_dgram_path; // Path to the Unix Domain Socket datagram file
    std::string transport; // Selected transport type: "tcp", "udp", "uds_stream", or "uds_dgram"
    std::string client_path; // Path for the client's own UDS datagram socket (used only in "uds_dgram" mode)

    static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"tcp-port", required_argument, 0, 'T'},
        {"udp-port", required_argument, 0, 'U'},
        {"stream-path", required_argument, 0, 's'},
        {"datagram-path", required_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    // Parse command-line arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "h:T:U:s:d:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h': server_host = optarg; break;
            case 'T': tcp_port = std::atoi(optarg); transport = "tcp"; break;
            case 'U': udp_port = std::atoi(optarg); transport = "udp"; break;
            case 's': uds_stream_path = optarg; transport = "uds_stream"; break;
            case 'd': uds_dgram_path = optarg; transport = "uds_dgram"; break;
            default:
                std::cerr << "Usage: " << argv[0] << " -h <host> -T <port> | -U <port> | -s <path> | -d <path>\n";
                return 1;
        }
    }

    // Validate mutual exclusivity of transport options
    int transport_count = (tcp_port != -1) + (udp_port != -1) + !uds_stream_path.empty() + !uds_dgram_path.empty();
    if (transport_count != 1) {
        std::cerr << "Error: Must specify exactly one of -T, -U, -s, or -d.\n";
        return 1;
    }

    int sock; // Socket fd
    struct sockaddr_un uds_addr{}; // Address struct for UDS
    struct addrinfo hints{}, *res; // Structs for resolving hostnames/IPs (used in TCP/UDP)
    char buffer[BUFFER_SIZE] = {0}; // Buffer for sending/receiving data

    if (transport == "tcp" || transport == "udp") {
        if (!server_host) { // Host name for TCP/UDP
            std::cerr << "Error: host (-h) is required for TCP/UDP.\n";
            return 1;
        }

        // Select the correct port based on which was specified
        int port = (tcp_port != -1) ? tcp_port : udp_port;

        // Prepare hints for address resolution (IPv4, stream or datagram socket)
        hints.ai_family = AF_INET;
        hints.ai_socktype = (transport == "tcp") ? SOCK_STREAM : SOCK_DGRAM;

        std::string port_str = std::to_string(port); // Convert port number to string for getaddrinfo
        // Resolve server address and port
        if (getaddrinfo(server_host, port_str.c_str(), &hints, &res) != 0) {
            perror("getaddrinfo");
            return 1;
        }

        // Create the socket
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) {
            perror("socket");
            freeaddrinfo(res);
            return 1;
        }

        if (transport == "tcp") // If it's TCP, establish a connection
        {
            if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) 
            {
                perror("connect");
                freeaddrinfo(res);
                close(sock);
                return 1;
            }
            std::cout << "Connected via TCP to " << server_host << ":" << port << "\n";
        } 
        else // If it's UDP, we don't need to establish a connection
        {
            std::cout << "Ready to send UDP messages to " << server_host << ":" << port << "\n";
        }
    } 
    else // uds_stream || uds_dgram
    {
        // Create a UNIX domain socket uds_stream/uds_dgram
        sock = socket(AF_UNIX, (transport == "uds_stream" ? SOCK_STREAM : SOCK_DGRAM), 0);
        if (sock < 0) {
            perror("socket (UDS)");
            return 1;
        }

        // Initialize and configure the server address structure
        memset(&uds_addr, 0, sizeof(uds_addr));
        uds_addr.sun_family = AF_UNIX;

        // Use the socket path from the command-line argument
        std::string path = (transport == "uds_stream") ? uds_stream_path : uds_dgram_path;
        strncpy(uds_addr.sun_path, path.c_str(), sizeof(uds_addr.sun_path) - 1);

        if (transport == "uds_stream") // For UDS stream, connect to the server
        {
            if (connect(sock, (struct sockaddr*)&uds_addr, sizeof(uds_addr)) < 0) 
            {
                perror("connect (UDS stream)");
                close(sock);
                return 1;
            }
            std::cout << "Connected to UDS stream at " << path << "\n";
        } 
        else // For UDS datagram, we don't need to connect
        {
            std::cout << "Ready to send UDS datagrams to " << path << "\n";
        }

        if (transport == "uds_dgram") 
        {
            // Generate a unique client socket path for this client socket using its process ID
            client_path = "/tmp/uds_client_" + std::to_string(getpid()) + ".sock";

            // Unlink this path just in case it was linked to another client before and never unlinked
            unlink(client_path.c_str()); 

            // Set up the client address struct for binding
            struct sockaddr_un client_addr{};
            client_addr.sun_family = AF_UNIX;
            strncpy(client_addr.sun_path, client_path.c_str(), sizeof(client_addr.sun_path) - 1);

            // Bind the client socket to its unique path
            if (bind(sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) 
            {
                perror("bind (UDS datagram client)");
                close(sock);
                return 1;
            }

            std::cout << "Bound client to UDS datagram socket at " << client_path << "\n";

            // Schedule automatic cleanup of the client socket file on process exit
            atexit([]() {
                unlink(("/tmp/uds_client_" + std::to_string(getpid()) + ".sock").c_str());
            });
        }
    }

    while (true) {
        std::string input;
        std::cout << "Enter command: ";
        std::getline(std::cin, input); // Read command from user

        if (input.empty()) break; // Exit loop if input is empty (user pressed Enter)

        if (transport == "tcp" || transport == "uds_stream") 
        {
            // Send the input command to the server
            send(sock, input.c_str(), input.size(), 0);

            // Receive response
            int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);

            if (bytes <= 0) break; // Exit if server closed connection or error
            buffer[bytes] = '\0'; // Null-terminate the response

            std::cout << "Server response:\n" << buffer << "\n"; // Print server response
        } 
        else // udp || uds_datagram
        {
            // Destination address setup
            struct sockaddr* send_addr;
            socklen_t send_len;

            if (transport == "udp")
            {
                // For UDP, use address from getaddrinfo()
                send_addr = (struct sockaddr*)res->ai_addr;
                send_len = res->ai_addrlen;
            } 
            else // uds_datagram
            {
                // For UDS datagram, use the server's UNIX socket address
                send_addr = (struct sockaddr*)&uds_addr;
                send_len = sizeof(uds_addr);
            }

            sendto(sock, input.c_str(), input.size(), 0, send_addr, send_len); // Send the message to the server

            // Prepare to receive reply
            struct sockaddr_storage reply_addr; // Struct to hold the address of the server
            socklen_t addrlen = sizeof(reply_addr);

            buffer[BUFFER_SIZE] = {0}; // Clear the buffer

            // Receive response from the server
            int bytes = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0,
                                (struct sockaddr*)&reply_addr, &addrlen);
            
            if (bytes < 0) {
                perror("recvfrom failed");
                break;
            }

            buffer[bytes] = '\0'; // Null-terminate the response
            std::cout << "Server response:\n" << buffer << "\n"; // Print server response
        }
    }

    unlink(client_path.c_str()); // Unlink the UDS datagram client socket file if it was created

    // Free dynamically allocated address info for TCP/UDP
    if (transport == "tcp" || transport == "udp") {
        freeaddrinfo(res);
    }

    close(sock); // Close the socket fd
    
    return 0;
}
