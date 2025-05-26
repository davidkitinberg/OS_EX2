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
#include <cstdlib>
#include <getopt.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

// Atom stock map: keeps track of current inventory
std::map<std::string, unsigned long long> atom_stock = {
    {"CARBON", 0},
    {"OXYGEN", 0},
    {"HYDROGEN", 0}
};

const unsigned long long MAX_STORAGE = 1000000000000000000ULL; // 10^18

// Molecule recipes: required atoms per molecule
std::map<std::string, std::map<std::string, int>> molecule_recipes = {
    {"WATER", {{"HYDROGEN", 2}, {"OXYGEN", 1}}},
    {"CARBON DIOXIDE", {{"CARBON", 1}, {"OXYGEN", 2}}},
    {"ALCOHOL", {{"CARBON", 2}, {"HYDROGEN", 6}, {"OXYGEN", 1}}},
    {"GLUCOSE", {{"CARBON", 6}, {"HYDROGEN", 12}, {"OXYGEN", 6}}}
};

// Handle ADD command over TCP
void handle_add(const std::string& cmd, int client_socket) {
    std::string response;
    std::istringstream iss(cmd);
    std::string action, atom;
    unsigned long long amount;

    // Parse input: expecting ADD <ATOM> <AMOUNT>
    iss >> action >> atom;
    if (!(iss >> amount)) {
        response = "ERROR: Missing or invalid amount\n";
        send(client_socket, response.c_str(), response.size(), 0);
        return;
    }

    // Handle valid ADD command
    if (action == "ADD" && atom_stock.find(atom) != atom_stock.end()) {
        if (atom_stock[atom] + amount > MAX_STORAGE) {
            response = "ERROR: Storage limit exceeded (max 10^18)\n";
        } else {
            atom_stock[atom] += amount;
            response = "Updated stock:\n";
            for (const auto& [key, val] : atom_stock) {
                response += key + ": " + std::to_string(val) + "\n";
            }
        }
    } else {
        response = "ERROR: Unknown command or atom type\n";
    }

    // Send back response to TCP client
    send(client_socket, response.c_str(), response.size(), 0);
}

// Handle DELIVER command (for both TCP & UDP)
std::string handle_deliver(const std::string& cmd) {
    std::istringstream iss(cmd);
    std::string action, molecule;
    int count;

    // Parse input: expecting DELIVER <MOLECULE> <AMOUNT>
    iss >> action >> std::ws;
    std::getline(iss, molecule, ' ');
    iss >> count;

    // Validate format and molecule type
    if (action != "DELIVER" || molecule_recipes.find(molecule) == molecule_recipes.end() || count <= 0) {
        return "ERROR: Invalid DELIVER command\n";
    }

    // Save current atom state for rollback if needed
    auto original_stock = atom_stock;

    // Check and deduct required atoms
    for (const auto& [atom, qty] : molecule_recipes[molecule]) {
        unsigned long long required = qty * count;
        if (atom_stock[atom] < required) {
            return "ERROR: Not enough atoms to deliver " + molecule + "\n";
        }
        atom_stock[atom] -= required;
    }

    return "SUCCESS: Delivered " + std::to_string(count) + " " + molecule + "\n";
}

int main(int argc, char* argv[]) {
    int tcp_fd, udp_fd, new_socket, activity, valread, sd, max_sd;
    struct sockaddr_in address, udp_addr;
    int optval = 1;
    int addrlen = sizeof(address), udp_len;
    char buffer[BUFFER_SIZE];
    int port = -1;

    // Parse command-line arguments using getopt
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                port = std::atoi(optarg); // User-defined port to bind to
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -p <port>" << std::endl;
                return 1;
        }
    }

    if (port == -1) {
        std::cerr << "Error: Port is required.\n";
        return 1;
    }

    fd_set readfds;
    int client_socket[MAX_CLIENTS] = {0}; // Array of active TCP client sockets

    // Create TCP socket
    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Create UDP socket
    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Shared address configuration for both protocols
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind both TCP and UDP sockets to the same port
    bind(tcp_fd, (struct sockaddr*)&address, sizeof(address));
    bind(udp_fd, (struct sockaddr*)&address, sizeof(address));
    listen(tcp_fd, 3); // Accept max 3 pending TCP connections

    std::cout << "molecule_supplier started on port " << port << std::endl;

    while (true) {
        // Prepare file descriptor set
        FD_ZERO(&readfds);
        FD_SET(tcp_fd, &readfds);
        FD_SET(udp_fd, &readfds);
        max_sd = std::max(tcp_fd, udp_fd);

        // Add all active TCP clients to set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        // Wait for activity on any socket
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select error");
            continue;
        }

        // Handle new incoming TCP connection
        if (FD_ISSET(tcp_fd, &readfds)) {
            new_socket = accept(tcp_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
            std::cout << "New connection, socket fd is " << new_socket << std::endl;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    break;
                }
            }
        }

        // Handle incoming UDP message
        if (FD_ISSET(udp_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            memset(buffer, 0, BUFFER_SIZE);
            int n = recvfrom(udp_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
            if (n > 0) {
                std::string response = handle_deliver(buffer); // Only DELIVER is allowed via UDP
                sendto(udp_fd, response.c_str(), response.size(), 0, (struct sockaddr*)&client_addr, client_len);
            }
        }

        // Handle TCP client commands
        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (FD_ISSET(sd, &readfds)) {
                valread = read(sd, buffer, BUFFER_SIZE);
                if (valread == 0) {
                    // Client disconnected
                    close(sd);
                    client_socket[i] = 0;
                } else {
                    buffer[valread] = '\0';
                    std::string cmd(buffer);
                    std::string response;

                    // Determine if it's an ADD or DELIVER command
                    if (cmd.find("DELIVER") == 0) {
                        response = handle_deliver(cmd);
                    } else {
                        handle_add(cmd, sd);
                        continue;
                    }

                    // Send DELIVER response to TCP client
                    send(sd, response.c_str(), response.size(), 0);
                }
            }
        }
    }

    return 0;
}
