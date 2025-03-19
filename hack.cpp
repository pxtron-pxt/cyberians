#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8888
#define BACKLOG 10
#define MAX_RESPONSE_SIZE 1024

// This function processes the log entry and performs basic classification
int classify_threat(const char *log_entry) {
    // Example classification logic: check the length of the log entry
    size_t log_length = strlen(log_entry);

    // Simple rule: if log length > 100, it's a threat
    if (log_length > 100) {
        return 1; // Threat
    } else {
        return 0; // No threat
    }
}

// Utility function to convert an integer to a string (itoa)
void itoa(int num, char *str) {
    int i = 0;
    int sign = num;

    if (num < 0) {
        num = -num;
    }

    do {
        str[i++] = num % 10 + '0';  // Get the next digit
    } while ((num /= 10) > 0);

    if (sign < 0) {
        str[i++] = '-';
    }

    str[i] = '\0';

    // Reverse the string to get the correct order
    int start = 0;
    int end = i - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
}

// This function handles HTTP requests
void handle_request(int client_socket) {
    char buffer[1024];
    char response[MAX_RESPONSE_SIZE];
    int read_size;
    // Read the incoming HTTP request
    read_size = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (read_size < 0) {
        perror("recv");
        return;
    }
    buffer[read_size] = '\0';

    // Look for the GET request with "/detect/" in the URL
    if (strncmp(buffer, "GET /detect/", 12) == 0) {
        // Extract the log entry from the URL (after "/detect/")
        const char *log_entry = buffer + 12;

        // Call the classification function to get the threat level (0: No threat, 1: Threat)
        int threat_level = classify_threat(log_entry);

        // Manually build the HTTP response in JSON format
        char threat_str[2];  // Only need one digit for the threat level (0 or 1)
        itoa(threat_level, threat_str);
        // Build the response manually (without snprintf)
        strcpy(response, "HTTP/1.1 200 OK\r\n");
        strcat(response, "Content-Type: application/json\r\n\r\n");
        strcat(response, "{\"Threat Level\": ");
        strcat(response, threat_str);
        strcat(response, "}");

    } else {
        // Return a 404 error if the request is not valid
        strcpy(response, "HTTP/1.1 404 Not Found\r\n");
        strcat(response, "Content-Type: application/json\r\n\r\n");
        strcat(response, "{\"error\": \"Invalid request\"}");
    }
    // Send the HTTP response back to the client
    send(client_socket, response, strlen(response), 0);
}

// Main function to set up the server and handle incoming connections
int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Create the server socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    // Set up the server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket to the defined port
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_socket, BACKLOG) < 0) {
        perror("listen");
        return 1;
    }

    printf("Server running on http://localhost:%d\n", PORT);
// Accept incoming client connections and handle them
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }

        // Handle the HTTP request from the client
        handle_request(client_socket);

        // Close the client socket after responding
        close(client_socket);
    }

    // Close the server socket (this line will not be reached in this infinite loop)
    close(server_socket);
    return 0;
}
