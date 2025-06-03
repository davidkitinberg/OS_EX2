#include <iostream>
#include <string>
#include <cstring>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <unistd.h>
#include <algorithm>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <getopt.h>
#include <set>

#define MAX_CLIENTS 10 // Max number of TCP clients
#define BUFFER_SIZE 1024 // Buffer size for messages

// Atom stock map: keeps track of current inventory
std::map<std::string, unsigned long long> atom_stock = {
    {"CARBON", 0},
    {"OXYGEN", 0},
    {"HYDROGEN", 0}
};

const unsigned long long MAX_STORAGE = 1000000000000000000ULL; // 10^18

// Molecule recipes: each molecule needs a specific number of atoms
std::map<std::string, std::map<std::string, int>> molecule_recipes = {
    {"WATER", {{"HYDROGEN", 2}, {"OXYGEN", 1}}},
    {"CARBON DIOXIDE", {{"CARBON", 1}, {"OXYGEN", 2}}},
    {"ALCOHOL", {{"CARBON", 2}, {"HYDROGEN", 6}, {"OXYGEN", 1}}},
    {"GLUCOSE", {{"CARBON", 6}, {"HYDROGEN", 12}, {"OXYGEN", 6}}}
};


// Handle ADD command over TCP && UDP
std::string process_add_command(const std::string& cmd) {
    std::istringstream iss(cmd);
    std::string action, atom;
    unsigned long long amount;
    std::string response;

    // Parse input: ADD <ATOM> <AMOUNT>
    iss >> action >> atom;
    if (!(iss >> amount)) {
        return "ERROR: Missing or invalid amount\n";
    }

    // Check if atom type exists and apply the add logic
    if (action != "ADD" || atom_stock.find(atom) == atom_stock.end()) 
    {
        return "ERROR: Unknown command or atom type\n";
    }

    if (atom_stock[atom] + amount > MAX_STORAGE) // Check for storage limit
    {
        return "ERROR: Storage limit exceeded (max 10^18)\n";
    }

    atom_stock[atom] += amount; // Update amount
    response = "Updated stock:\n";
    for (const auto& [key, val] : atom_stock) { // Print the inventory
        response += key + ": " + std::to_string(val) + "\n";
    }

    return response;
}


// Handle DELIVER command (for both TCP & UDP)
std::string handle_deliver(const std::string& cmd) {
    std::istringstream iss(cmd);
    std::string action, molecule, part;
    long long count = -1;

    // Parse input: expecting DELIVER <MOLECULE> <AMOUNT>
    iss >> action;

    while (iss >> part) 
    {
        if (std::all_of(part.begin(), part.end(), ::isdigit)) 
        {
            try 
            {
                count = std::stoll(part);
            } 
            catch (const std::exception&) 
            {
                return "ERROR: Invalid or out-of-range molecule count\n";
            }
            break;
        }
        if (!molecule.empty()) molecule += " ";
        molecule += part;
    }

    // Validate the input format and that the molecule exists
    if (action != "DELIVER" || molecule_recipes.find(molecule) == molecule_recipes.end() || count <= 0) {
        return "ERROR: Invalid DELIVER command\n";
    }

    // Backup current stock to revert in case of failure
    auto original_stock = atom_stock;

    // Try to deduct required atoms for the molecule
    for (const auto& [atom, qty] : molecule_recipes[molecule]) 
    {
        unsigned long long required = qty * count;
        if (atom_stock[atom] < required) { // If there are'nt enough atoms to make the wanted amount of molecules
            return "ERROR: Not enough atoms to deliver " + molecule + "\n";
        }
        atom_stock[atom] -= required; // Update stock
    }

    return "SUCCESS: Delivered " + std::to_string(count) + " " + molecule + "\n";
}

int main(int argc, char* argv[]) {
    // Socket and control variables
    int tcp_fd, udp_fd, new_socket, activity, valread, sd, max_sd;
    struct sockaddr_in address;
    int optval = 1;
    char buffer[BUFFER_SIZE];
    int port = -1;

    std::set<std::string> known_udp_clients; // Set to track known UDP clients (IP:PORT)

    // Parse command-line arguments (port number)
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) 
    {
        switch (opt) 
        {
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
        return 1;
    }


    // Set of sockets for select()
    fd_set readfds;
    int client_socket[MAX_CLIENTS] = {0}; // TCP client connections

    // Setup TCP socket
    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Setup UDP socket
    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Configure address for binding
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind TCP and UDP sockets to same address
    bind(tcp_fd, (struct sockaddr*)&address, sizeof(address));
    bind(udp_fd, (struct sockaddr*)&address, sizeof(address));
    listen(tcp_fd, 3); // Start TCP listener

    std::cout << "molecule_supplier started on port " << port << std::endl;

    while (true) 
    {
        // Clear and prepare file descriptor set
        FD_ZERO(&readfds); // Clear and prepare file descriptor set
        FD_SET(tcp_fd, &readfds); // Add TCP fd to the readfds
        FD_SET(udp_fd, &readfds); // Add UDP fd to the readfds
        max_sd = std::max(tcp_fd, udp_fd); // Max fd number

        // Add active TCP sockets to the fd set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        // Wait for activity (TCP or UDP or client)
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select error");
            continue;
        }

        // Handle new TCP connection
        if (FD_ISSET(tcp_fd, &readfds)) // Checks whether the TCP socket (tcp_fd) is ready for reading
        {
            struct sockaddr_in client_addr; // Struct to store the client's address
            socklen_t client_len = sizeof(client_addr); // Initialize client_len to the size of that struct
            new_socket = accept(tcp_fd, (struct sockaddr*)&client_addr, &client_len); // Accepts the incoming TCP connection

            char client_ip[INET_ADDRSTRLEN]; 
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN); // Converts the client’s IP address to string
            int client_port = ntohs(client_addr.sin_port);

            std::cout << "New connection, socket fd is TCP from " << client_ip << ":" << client_port << std::endl;

            // Store new socket
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    break;
                }
            }
        }

        // Handle new UDP message
        if (FD_ISSET(udp_fd, &readfds)) // Checks if the UDP socket has received a message
        {
            struct sockaddr_in client_addr; // Prepare sockaddr_in struct to store the client's address info
            socklen_t client_len = sizeof(client_addr);
            memset(buffer, 0, BUFFER_SIZE); // Clears the buffer
            // Reads a UDP datagram from the socket into buffer
            int n = recvfrom(udp_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
            if (n > 0) // If we recieved a message
            {
                // Track new UDP client
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN); // Converts the client's IP to string
                int client_port = ntohs(client_addr.sin_port);
                std::string client_id = std::string(client_ip) + ":" + std::to_string(client_port); // Constructs a unique ID for the client
                if (known_udp_clients.find(client_id) == known_udp_clients.end()) // If its a new client, log the connection
                {
                    known_udp_clients.insert(client_id);
                    std::cout << "New connection, socket fd is UDP from " << client_id << std::endl;
                }

                std::string cmd(buffer);
                std::string response; // Store the response

                // Parse and handle UDP command
                if (cmd.find("DELIVER") == 0) // If the request is DELIVER
                {
                    response = handle_deliver(cmd); // Call handle deliver
                } 
                else if (cmd.find("ADD") == 0) // If the request is ADD
                {
                    response = process_add_command(cmd);
                }
                else // Generic error
                {
                    response = "ERROR: Unsupported command\n";
                }

                // Send UDP response back to the same client that sent the request
                sendto(udp_fd, response.c_str(), response.size(), 0, (struct sockaddr*)&client_addr, client_len);
            }
        }





        // Handle existing TCP clients' messages
        for (int i = 0; i < MAX_CLIENTS; i++) // Loop over the connected TCP clients
        {
            sd = client_socket[i]; // Store the socket file descriptor of client i
            if (FD_ISSET(sd, &readfds)) // Check if this client’s socket has incoming data
            {
                valread = read(sd, buffer, BUFFER_SIZE); // Read incoming data from the client into buffer
                if (valread == 0) // If the incoming data is empty message
                {
                    // TCP client disconnected
                    close(sd);
                    client_socket[i] = 0;
                } 
                else 
                {
                    buffer[valread] = '\0'; // Add end of string
                    std::string cmd(buffer); // Convert the request to string
                    std::string response; 

                    // Determine command type and handle it
                    if (cmd.find("DELIVER") == 0) {
                        response = handle_deliver(cmd); // Send to handle deliver
                    } else if (cmd.find("ADD") == 0)
                    {
                        response = process_add_command(cmd);
                    }

                    // Send TCP response
                    send(sd, response.c_str(), response.size(), 0);
                }
            }
        }
    }

    return 0;
}
