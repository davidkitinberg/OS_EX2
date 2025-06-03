#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <csignal>
#include <getopt.h>
#include <set>
#include <climits>
#include <fcntl.h>
#include <algorithm>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAX_CLIENTS 10 // Max number of TCP clients
#define BUFFER_SIZE 1024 // Buffer size for messages

// Struct used for mmap-based persistent storage
struct AtomInventory {
    unsigned long long carbon;
    unsigned long long oxygen;
    unsigned long long hydrogen;
};

AtomInventory* shared_inventory = nullptr; // pointer to the mmap'd region
int save_fd = -1;
std::string save_file_path;

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

// Lock the writing one a file
void lock_file(int fd) {
    struct flock lock = {
        .l_type = F_WRLCK, // Write lock
        .l_whence = SEEK_SET, // From the beginning of the file
        .l_start = 0, // Offset 0
        .l_len = sizeof(AtomInventory) // Lock only the relevant region (entire AtomInventory struct)
    };

    // Block until the lock is acquired
    if (fcntl(fd, F_SETLKW, &lock) == -1) {
        perror("fcntl lock");
        exit(1);
    }
}

// Unlock the file - after the process finished writing/reading from it
void unlock_file(int fd) {
    struct flock lock = {
        .l_type = F_UNLCK, // Unlock
        .l_whence = SEEK_SET, // From the beginning of the file
        .l_start = 0, // Offset 0
        .l_len = sizeof(AtomInventory)// Unlock only the relevant region (entire AtomInventory struct)
    };

    // Release the lock
    if (fcntl(fd, F_SETLK, &lock) == -1) {
        perror("fcntl unlock");
        exit(1);
    }
}

// Copies current in-memory atom stock into the shared memory file
// Ensures atomic and synchronized update using file locking
void sync_to_file() {
    if (!shared_inventory) return; // Exit if shared memory is not initialized (-f flag)

    lock_file(save_fd);// Lock the file before writing to it

    // Write from the current atom stock to the file
    shared_inventory->carbon = atom_stock["CARBON"];
    shared_inventory->oxygen = atom_stock["OXYGEN"];
    shared_inventory->hydrogen = atom_stock["HYDROGEN"];

    // Ensure changes are flushed to disk immediately
    msync(shared_inventory, sizeof(AtomInventory), MS_SYNC);

    unlock_file(save_fd); // After we finished writing - release the lock
}


// Updates the in-memory atom stock from the shared memory file
// Ensures atomic and consistent read using file locking
void sync_from_file() {
    if (!shared_inventory) return; // Exit if shared memory is not initialized (-f flag)

    lock_file(save_fd); // Lock the file before reading from it

    // Update the atom stock from the file
    atom_stock["CARBON"] = shared_inventory->carbon;
    atom_stock["OXYGEN"] = shared_inventory->oxygen;
    atom_stock["HYDROGEN"] = shared_inventory->hydrogen;

    unlock_file(save_fd); // After we finished reading - release the lock
}


// Initializes the shared file for the servers
void init_save_file(const std::string& path) {

    // Check if the file already exists (to decide whether to load or initialize stock)
    bool file_exists = (access(path.c_str(), F_OK) == 0);

    // Open the file for reading and writing, create if it doesn't exist
    save_fd = open(path.c_str(), O_RDWR | O_CREAT, 0666);
    if (save_fd < 0) {
        perror("open save file");
        exit(1);
    }

    // Ensure the file is large enough to store the AtomInventory struct
    if (ftruncate(save_fd, sizeof(AtomInventory)) == -1) {
        perror("ftruncate");
        exit(1);
    }

    // Map the file into memory so all processes can share it
    shared_inventory = (AtomInventory*) mmap(nullptr, // The kernel chooses the mapping address
                                            sizeof(AtomInventory), // Size of the region to map
                                             PROT_READ | PROT_WRITE, // Allow read and write in this file region
                                             MAP_SHARED, // Changes in the file are shared between processes
                                              save_fd, // File descriptor to map
                                              0); // Offset in the file
    // Check for failure of mmap
    if (shared_inventory == MAP_FAILED) {
        perror("Error: Could not initialize file into memory using mmap");
        exit(1);
    }

    // Either load from file or save the current stock depending on file existence
    if (file_exists) 
    {
        sync_from_file(); // override atom_stock with file content
    } 
    else 
    {
        sync_to_file(); // Write the new stock from the commend line to the file
    }
}


// Handle ADD command over TCP && UDP
std::string process_add_command(const std::string& cmd) {

    sync_from_file(); // Sync stock from file before using the stock

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
    sync_to_file();


    response = "Updated stock:\n";
    for (const auto& [key, val] : atom_stock) { // Print the inventory
        response += key + ": " + std::to_string(val) + "\n";
    }

    return response;
}



// Handle DELIVER command (for both TCP & UDP)
std::string handle_deliver(const std::string& cmd) {

    sync_from_file(); // Sync stock from file before using the stock

    std::istringstream iss(cmd);
    std::string action, molecule, part;
    long long count = -1;

    // Parse input: DELIVER <MOLECULE> <AMOUNT>
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
        unsigned long long required = static_cast<unsigned long long>(qty) * count;
        
        if (atom_stock[atom] < required) { // If there are'nt enough atoms to make the wanted amount of molecules
            return "ERROR: Not enough atoms to deliver " + molecule + "\n";
        }
        atom_stock[atom] -= required; // Update stock
    }

    sync_to_file();
    return "SUCCESS: Delivered " + std::to_string(count) + " " + molecule + "\n";
}



// Helper function to calculate max number of drinks from stock
int get_max_possible(std::vector<std::string> required_molecules) {

    sync_from_file(); // Sync stock from file before using the stock

    std::map<std::string, unsigned long long> total_needed;

    // Sum up total atoms required for all molecules that make up the drink
    for (const std::string& mol : required_molecules) {
        if (molecule_recipes.find(mol) == molecule_recipes.end()) {
            std::cerr << "ERROR: Unknown molecule in GEN command: " << mol << std::endl;
            return 0;
        }
        for (const auto& [atom, count] : molecule_recipes[mol]) {
            total_needed[atom] += count;
        }
    }

    // Calculate how many drinks can be made based on current atom_stock
    unsigned long long max_drinks = ULLONG_MAX;
    for (const auto& [atom, needed_per_drink] : total_needed) {
        if (atom_stock.find(atom) == atom_stock.end() || needed_per_drink == 0) return 0;
        max_drinks = std::min(max_drinks, atom_stock[atom] / needed_per_drink);
    }

    return static_cast<int>(max_drinks);
}

// Alarm handler
void handle_alarm(int sig) {
    std::cout << "\nTimeout reached. Shutting down server...\n";
    exit(0);
}

static struct option long_options[] = {
    {"oxygen", required_argument, 0, 'o'},
    {"carbon", required_argument, 0, 'c'},
    {"hydrogen", required_argument, 0, 'h'},
    {"timeout", required_argument, 0, 't'},
    {"tcp-port", required_argument, 0, 'T'},
    {"udp-port", required_argument, 0, 'U'},
    {"stream-path", required_argument, 0, 's'},
    {"datagram-path", required_argument, 0, 'd'},
    {"save-file", required_argument, 0, 'f'},
    {0, 0, 0, 0}
};


int main(int argc, char* argv[]) {
    // Socket and control variables
    int new_socket, activity, sd, max_sd;
    struct sockaddr_in address_TCP; // Sock address for TCP
    struct sockaddr_in address_UDP; // Sock address for UDP
    std::string uds_stream_path; // Path for UDS stream socket
    std::string uds_dgram_path; // Path for UDS datagram socket

    int optval = 1; // Option value used for setting socket options
    char buffer[BUFFER_SIZE]; // Buffer for reading data from sockets

    std::set<std::string> known_udp_clients; // Set to track known UDP clients (IP:PORT)

    // Parse command-line arguments
    int opt;
    int tcp_port = -1; // UDP port number
    int udp_port = -1; // TCP port number
    int timeout_seconds = -1; // Timeout out for any channel input on select
    while ((opt = getopt_long(argc, argv, "o:c:h:t:T:U:s:d:f:", long_options, NULL)) != -1) 
    {
        switch (opt) 
        {
            case 'o': atom_stock["OXYGEN"] = std::stoull(optarg); break;
            case 'c': atom_stock["CARBON"] = std::stoull(optarg); break;
            case 'h': atom_stock["HYDROGEN"] = std::stoull(optarg); break;
            case 't': timeout_seconds = std::stoi(optarg); break;
            case 's': uds_stream_path = optarg; break;
            case 'd': uds_dgram_path = optarg; break;
            case 'T': tcp_port = std::stoi(optarg); break;
            case 'U': udp_port = std::stoi(optarg); break;
            case 'f': save_file_path = optarg; break;
            default:
                std::cerr << "\nUsage: " << argv[0] 
                        << " [-T <tcp_port>] [-U <udp_port>] [--stream-path <path>] [--datagram-path <path>] "
                        << "[--oxygen N] [--carbon N] [--hydrogen N] [--timeout SEC]\n";
                return 1;
        }
    }

    // If we don'y have a saved file yet
    if (!save_file_path.empty()) {
        init_save_file(save_file_path);
    }

    // Validate exclusive OR for stream
    if ((tcp_port != -1 && !uds_stream_path.empty()) ||
        (tcp_port == -1 && uds_stream_path.empty())) {
        std::cerr << "Error: Must specify exactly one of --tcp-port OR --stream-path\n";
        return 1;
    }

    // Validate exclusive OR for datagram
    if ((udp_port != -1 && !uds_dgram_path.empty()) ||
        (udp_port == -1 && uds_dgram_path.empty())) {
        std::cerr << "Error: Must specify exactly one of --udp-port OR --datagram-path\n";
        return 1;
    }


    // We want to make STDIN non-blocking so it won't freeze the entire main loop of select
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK); // make stdin non-blocking
    std::string stdin_buf; // Use a string buffer to accumulate stdin input

    
    fd_set readfds; // Set of sockets fd for select()
    int client_socket[MAX_CLIENTS] = {0}; // TCP client connections

    // Initialize all file descriptors before logic handling
    int uds_stream_fd = -1, uds_dgram_fd = -1;
    int tcp_fd = -1, udp_fd = -1;


    struct sockaddr_un addr_uds_stream, addr_uds_dgram; // Initialize domain socket addresses structs

    // Create TCP socket if the TCP port was specified
    if (tcp_port != -1) 
    {
        tcp_fd = socket(AF_INET, SOCK_STREAM, 0); // Create a TCP socket
        if (tcp_fd < 0) {
            perror("Error creating the TCP socket");
            exit(1);
        }
        // Allow the port to be reused after the program terminates
        setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        // Initialize the TCP address struct
        memset(&address_TCP, 0, sizeof(address_TCP));
        address_TCP.sin_family = AF_INET; // IPv4
        address_TCP.sin_addr.s_addr = INADDR_ANY; 
        address_TCP.sin_port = htons(tcp_port);

        // Bind the socket to the specified IP and port
        if (bind(tcp_fd, (struct sockaddr*)&address_TCP, sizeof(address_TCP)) < 0) {
            perror("bind TCP");
            exit(1);
        }

        // Listen for incoming TCP connections
        if (listen(tcp_fd, 3) < 0) {
            perror("listen TCP");
            exit(1);
        }

        std::cout << "TCP listening on port " << tcp_port << std::endl;
    }


    // Create UDP socket if the UDP port was specified
    if (udp_port != -1) 
    {
        // Create a UDP socket
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) {
            perror("Error creating UDP socket");
            exit(1);
        }
        // Allow the port to be reused after the program terminates
        setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        // Initialize the UDP address struct
        memset(&address_UDP, 0, sizeof(address_UDP));
        address_UDP.sin_family = AF_INET;
        address_UDP.sin_addr.s_addr = INADDR_ANY;
        address_UDP.sin_port = htons(udp_port);

        // Bind the socket to the specified IP and port
        if (bind(udp_fd, (struct sockaddr*)&address_UDP, sizeof(address_UDP)) < 0) {
            perror("bind UDP");
            exit(1);
        }

        std::cout << "UDP bound to port " << udp_port << std::endl;
    }


    // Create UDS stream socket if requested
    if (!uds_stream_path.empty()) 
    {
        // Create a UDS stream socket
        uds_stream_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (uds_stream_fd < 0) {
            perror("Error creating UDS stream socket");
            exit(1);
        }
        // Unlink this path just in case it was linked to another client before and never unlinked
        unlink(uds_stream_path.c_str());

        // Initialize the USD stream address struct
        memset(&addr_uds_stream, 0, sizeof(addr_uds_stream));
        addr_uds_stream.sun_family = AF_UNIX; // Use Unix domain
        strncpy(addr_uds_stream.sun_path, uds_stream_path.c_str(), sizeof(addr_uds_stream.sun_path) - 1);

        // Bind the socket to the file path
        if (bind(uds_stream_fd, (struct sockaddr*)&addr_uds_stream, sizeof(addr_uds_stream)) < 0) {
            perror("Error trying to bind UDS stream to path");
            exit(1);
        }

        // Listen for incoming USD stream connections
        if (listen(uds_stream_fd, 3) < 0) {
            perror("listen UDS stream");
            exit(1);
        }

        std::cout << "UDS Stream listening on " << uds_stream_path << std::endl;
    }

    // Create UDS dgram socket if requested
    if (!uds_dgram_path.empty()) 
    {
        // Create a UDS dgram socket
        uds_dgram_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (uds_dgram_fd < 0) {
            perror("Error creating UDS datagram socket");
            exit(1);
        }
        // Unlink this path just in case it was linked to another client before and never unlinked
        unlink(uds_dgram_path.c_str());

        // Initialize the USD dgram address struct
        memset(&addr_uds_dgram, 0, sizeof(addr_uds_dgram));
        addr_uds_dgram.sun_family = AF_UNIX;
        strncpy(addr_uds_dgram.sun_path, uds_dgram_path.c_str(), sizeof(addr_uds_dgram.sun_path) - 1);

        // Bind the socket to the specified filesystem path
        if (bind(uds_dgram_fd, (struct sockaddr*)&addr_uds_dgram, sizeof(addr_uds_dgram)) < 0) {
            perror("Error trying to bind UDS datagram to path");
            exit(1);
        }

        std::cout << "UDS Datagram bound to " << uds_dgram_path << std::endl;
    }



    // Timeout handling
    if (timeout_seconds > 0) {
    signal(SIGALRM, handle_alarm); // Set handler
    alarm(timeout_seconds); // Start initial alarm
    }

    

    while (true)
    {
        FD_ZERO(&readfds); // Clear and prepare file descriptor set

        // If we recieve uds/tcp/udp arguments, add their file descriptor to the file descriptor set
        if (tcp_fd != -1) FD_SET(tcp_fd, &readfds);
        if (udp_fd != -1) FD_SET(udp_fd, &readfds);
        if (uds_stream_fd != -1) FD_SET(uds_stream_fd, &readfds); 
        if (uds_dgram_fd != -1) FD_SET(uds_dgram_fd, &readfds);

        FD_SET(STDIN_FILENO, &readfds); // Add STDIN to read set

        // Initial max_sd to tell select number of bits in the fd_set it needs to scan
        // Add all existing TCP and UDS-STREAM client sockets
        max_sd = STDIN_FILENO;
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            sd = client_socket[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        // Update max_sd with all server listening sockets
        max_sd = std::max(max_sd, tcp_fd);
        max_sd = std::max(max_sd, udp_fd);
        max_sd = std::max(max_sd, uds_stream_fd);
        max_sd = std::max(max_sd, uds_dgram_fd);
        

        // Wait for activity on one of the fds (select())
        activity = select(max_sd + 1, &readfds, nullptr, nullptr, nullptr);
        if (activity < 0) {
            perror("Error in select activity");
            continue;
        }
        if (timeout_seconds > 0) alarm(timeout_seconds); // reset timeout timer



        // handle STDIN input
        if (FD_ISSET(STDIN_FILENO, &readfds)) // Select detects activity in STDIN
        {
            char tmp[256]; // Temporary buffer
            ssize_t nbytes = read(STDIN_FILENO, tmp, sizeof(tmp)); // Number of bytes read by STDIN
            if (nbytes > 0) 
            {
                stdin_buf.append(tmp, nbytes); // accumulate what we got
                size_t pos; // Number of bytes of current new line

                // The loop runs as long as there’s at least one complete line in stdin_buf
                while ((pos = stdin_buf.find('\n')) != std::string::npos) 
                {
                    std::string line = stdin_buf.substr(0, pos); // Extract the full line
                    stdin_buf.erase(0, pos + 1); // Removes the new line from the buffer

                    // Removes trailing spaces/carriage returns/tabs
                    line.erase(line.find_last_not_of(" \t\r") + 1);

                    // Handle the command - call get_max_possible with the correct recipe 
                    if (line == "GEN SOFT DRINK") 
                    {
                        std::cout << "Can make " << get_max_possible(
                                    {"WATER","CARBON DIOXIDE","GLUCOSE"})
                                << " SOFT DRINK(s)\n";
                    } 
                    else if (line == "GEN VODKA") 
                    {
                        std::cout << "Can make " << get_max_possible(
                                    {"WATER","GLUCOSE","ALCOHOL"})
                                << " VODKA(s)\n";
                    } 
                    else if (line == "GEN CHAMPAGNE") 
                    {
                        std::cout << "Can make " << get_max_possible(
                                    {"WATER","CARBON DIOXIDE","ALCOHOL"})
                                << " CHAMPAGNE(s)\n";
                    } 
                    else if (line == "QUIT") 
                    {
                        std::cout << "Shutting down server…\n";
                        // Close all fds and unlink sockets
                        return EXIT_SUCCESS; // Exit main
                    } 
                    else if (!line.empty()) 
                    {
                        std::cout << "Unknown command: " << line << '\n';
                    }
                }
            }
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
            for (int i = 0; i < MAX_CLIENTS; i++) 
            {
                if (client_socket[i] == 0) 
                {
                    client_socket[i] = new_socket;
                    break;
                }
            }
        }

        // Handle new UDS-STREAM connections
        if (uds_stream_fd != -1 && FD_ISSET(uds_stream_fd, &readfds)) 
        {
            new_socket = accept(uds_stream_fd, nullptr, nullptr);
            if (new_socket >= 0) 
            {
                std::cout << "New connection, socket fd is UDS-STREAM\n";
                // Make UDS STREAN non-blocking
                int fl = fcntl(new_socket,F_GETFL,0); 
                fcntl(new_socket,F_SETFL,fl|O_NONBLOCK);

                // Store new socket
                for (int i = 0; i < MAX_CLIENTS; ++i)
                {
                    if (client_socket[i] == 0) 
                    { 
                        client_socket[i] = new_socket; break; 
                    }
                }
                    
            }
        }

        // Handle new UDP message
        if (udp_fd != -1 && FD_ISSET(udp_fd, &readfds)) // Checks if the UDP socket has received a message
        {

            struct sockaddr_in client_addr; // Prepare sockaddr_in struct to store the client's address info
            socklen_t client_len = sizeof(client_addr);
            memset(buffer, 0, BUFFER_SIZE); // Clears the buffer
            // Reads a UDP datagram from the socket into buffer
            int n = recvfrom(udp_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);

            if (n > 0) // If we received a message
            {
                // Track new UDP client
                char client_ip[INET_ADDRSTRLEN]; 
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN); // Converts the client's IP to string
                int client_port = ntohs(client_addr.sin_port);
                std::string client_id = std::string(client_ip)+":"+std::to_string(ntohs(client_port));
                if (known_udp_clients.insert(client_id).second)
                {
                    std::cout << "New connection, socket fd is UDP from " << client_id << '\n';
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



        // Handle incoming connection on UDS dgram socket
        if (uds_dgram_fd != -1 && FD_ISSET(uds_dgram_fd, &readfds)) 
        {
            struct sockaddr_un client_addr; 
            socklen_t client_len = sizeof(client_addr);
            memset(buffer,0,BUFFER_SIZE); // Clear buffer for new input

            // Receive the datagram and capture the client's address
            int bytes = recvfrom(uds_dgram_fd, buffer, BUFFER_SIZE, 0,
                                (struct sockaddr*)&client_addr, &client_len);
            if (bytes > 0) 
            {
                std::string cmd(buffer); // Convert the buffer into a string command
                std::string response;

                // Process the command
                if (cmd.find("DELIVER") == 0)
                    response = handle_deliver(cmd);
                else if (cmd.find("ADD") == 0)
                    response = process_add_command(cmd);
                else
                    response = "ERROR: Unsupported command\n";

                // Send the response back to the client at the captured address
                sendto(uds_dgram_fd, response.c_str(), response.size(), 0,
                    (struct sockaddr*)&client_addr, client_len);
            }
        }


        // Handle existing TCP and UDS-STREAM client's messages
        for (int i = 0; i < MAX_CLIENTS; ++i) 
        {
            sd = client_socket[i]; // Store the socket file descriptor of client i
            if (sd == 0 || !FD_ISSET(sd, &readfds)) continue; // Check if this client’s socket has incoming data

            int n = read(sd, buffer, BUFFER_SIZE); // Read incoming data from the client into buffer
            if (n <= 0) { // If the incoming data is empty message
                close(sd); // TCP client disconnected
                client_socket[i] = 0;
                continue;
            }
            buffer[n] = '\0'; // Add end of string

            std::string cmd(buffer); // Convert the request to string
            std::string response; 


            // Determine command type and handle it
            if (cmd.find("DELIVER") == 0) {
                response = handle_deliver(cmd); // Send to handle deliver
            } 
            else if (cmd.find("ADD") == 0)
            {
                response = process_add_command(cmd);
            }
            else 
            {
                response = "ERROR: Unsupported command\n";
            }

            // Send response
            send(sd, response.c_str(), response.size(), 0);
        }
    }


    return EXIT_SUCCESS;
}
