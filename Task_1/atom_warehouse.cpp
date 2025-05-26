#include <iostream>
#include <string>
#include <cstring>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>

//#define PORT 12345
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

// Atom stock map: keeps track of current inventory
std::map<std::string, unsigned long long> atom_stock = {
    {"CARBON", 0},
    {"OXYGEN", 0},
    {"HYDROGEN", 0}
};

const unsigned long long MAX_STORAGE = 1000000000000000000ULL; // 10^18

// Handle a single command received from a client
void handle_command(const std::string& cmd, int client_socket) {
    std::string response;
    std::istringstream iss(cmd);
    std::string action, atom;
    unsigned long long amount;

    // Parse input: expecting "ADD <ATOM> <AMOUNT>"
    iss >> action >> atom;
    if (!(iss >> amount)) {
        response = "ERROR: Missing or invalid amount\n";
        send(client_socket, response.c_str(), response.size(), 0);
        return;
    }

    if (action == "ADD" && atom_stock.find(atom) != atom_stock.end()) // Valid command — update atom stock
    {
        if (atom_stock[atom] + amount > MAX_STORAGE) // Atom stock size limitation
        {
            response = "ERROR: Storage limit exceeded (max 10^18)\n";
        } else 
        {
            atom_stock[atom] += amount; // Update stock amount

            // Build stock status response
            response = "Updated stock:\n";
            for (const auto& [key, val] : atom_stock) 
            {
                response += key + ": " + std::to_string(val) + "\n";
            }
        }
    } else // Invalid command or unknown atom
    {
        response = "ERROR: Unknown command or atom type\n";
    }

    // Send response back to client
    send(client_socket, response.c_str(), response.size(), 0);
}

int main(int argc, char* argv[]) {
    int server_fd, new_socket, activity, valread, sd, max_sd;
    struct sockaddr_in address;
    //int opt = 1;
    int optval = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];
    int port = -1;


    // Parse command-line argument using getopt
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                port = std::atoi(optarg);
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -p <port>" << std::endl;
                return 1;
        }
    }

    if (port == -1) {
        std::cerr << "Error: Port is required.\n";
        std::cerr << "Usage: " << argv[0] << " -p <port>" << std::endl;
        return 1;
    }

    fd_set readfds;
    int client_socket[MAX_CLIENTS] = {0}; // Array of client sockets

    // Create server socket (IPv4, TCP)
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Allow reuse of port
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Prepare server address structure
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind socket to address and port
    bind(server_fd, (struct sockaddr*)&address, sizeof(address));

    // Start listening for incoming connections (max 3 in backlog queue)
    listen(server_fd, 3);

    std::cout << "atom_warehouse started on port " << port << std::endl;

    
    while (true) // Main loop to handle connections
    {
        // Clear and rebuild the read set
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        // Add all active client sockets to the read set
        for (int i = 0; i < MAX_CLIENTS; i++) 
        {
            sd = client_socket[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        // Use select() for IO multiplexing
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select error");
            continue;
        }

        // Check if there's a new incoming connection
        if (FD_ISSET(server_fd, &readfds)) 
        {
            new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
            std::cout << "New connection, socket fd is " << new_socket << std::endl;

            // Add new client socket to array
            for (int i = 0; i < MAX_CLIENTS; i++) 
            {
                if (client_socket[i] == 0) 
                {
                    client_socket[i] = new_socket;
                    break;
                }
            }
        }

        // Handle activity on existing client sockets
        for (int i = 0; i < MAX_CLIENTS; i++) 
        {
            sd = client_socket[i];
            if (FD_ISSET(sd, &readfds)) 
            {
                valread = read(sd, buffer, BUFFER_SIZE);
                if (valread == 0) // Client disconnected — clean up
                {
                    close(sd);
                    client_socket[i] = 0;
                } 
                else // Null-terminate and handle the command
                {
                    buffer[valread] = '\0';
                    handle_command(buffer, sd);
                }
            }
        }
    }

    return 0;
}
