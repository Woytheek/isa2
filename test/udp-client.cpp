#include <iostream>
#include <cstring>   // For memset
#include <sys/socket.h> // For socket
#include <netinet/in.h> // For sockaddr_in, htons
#include <arpa/inet.h>  // For inet_addr
#include <unistd.h>     // For close

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"  // Change to server's IP if needed

int main() {
    // Step 1: Create a socket
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return -1;
    }

    // Step 2: Setup the server address struct
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));  // Clear memory
    server_addr.sin_family = AF_INET;             // IPv4
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP); // Server IP address
    server_addr.sin_port = htons(SERVER_PORT);    // Server port

    // Step 3: Send a message to the server
    const char *message = "Hello, UDP Server!";
    int bytes_sent = sendto(udp_socket, message, strlen(message), 0, 
                            (struct sockaddr*)&server_addr, sizeof(server_addr));

    if (bytes_sent < 0) {
        std::cerr << "Error: Failed to send message" << std::endl;
    } else {
        std::cout << "Message sent to server!" << std::endl;
    }

    // Close the socket
    close(udp_socket);
    
    return 0;
}
