#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "hello-dns/tdns/tdns-c.h"

#define DNS_PORT 53
#define BUFFER_SIZE 2048 

void print_str_in_hex (const char *str, ssize_t len)
{
    for (ssize_t i = 0; i < len; i++) {
        printf ("%02x", str[i]);
    }  
    printf("\n");
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr, delegate_addr;
    socklen_t client_len = sizeof(client_addr), delegate_len = sizeof(delegate_addr);
    char buffer[BUFFER_SIZE];

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(DNS_PORT);

    // Bind socket to address
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Socket bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", DNS_PORT);
    struct TDNSServerContext *context = TDNSInitAuth();
    /* utexas.edu zone */
    TDNSCreateZone(context, "utexas.edu");
    TDNSAddEntry(context, "utexas.edu", "cs", "40.0.0.10", "ns.cs.utexas.edu");
    TDNSAddEntry(context, "cs.utexas.edu", "ns", "50.0.0.10", NULL);
    TDNSAddEntry(context, "utexas.edu", "www", "20.0.0.10", NULL);

    /* reverse zone */
    TDNSCreateZone(context, "in-addr.arpa");
    TDNSAddPTREntry(context, "in-addr.arpa", "40.0.0.10", "cs.utexas.edu");
    TDNSAddPTREntry(context, "in-addr.arpa", "50.0.0.10", "ns.cs.utexas.edu");
    TDNSAddPTREntry(context, "in-addr.arpa", "20.0.0.10", "www.utexas.edu");

    // Receive message
    ssize_t bytes_received;
    struct TDNSQuery *query;
    struct TDNSResponse response;
    struct TDNSFindResult result;
    while (1) {
        bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                   (struct sockaddr *)&client_addr, &client_len);
        if (bytes_received == -1) {
            perror("Error receiving message");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Print received message
        printf("Received message from %s:%d, message size: %lu\n", 
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), bytes_received);
        query = TDNSParseQuery(buffer, bytes_received, &response);
        printf("qtype: %u, qname: %s\n", query->qtype, query->qname);
        printf("Response qtype: %u, qname: %s, qclass: %u\n", response.qtype, response.qname, response.qclass);
        switch (query->qtype) {
            case A:
            case AAAA:
            case PTR:
            case NS:
                if (TDNSFind(context, query->qname, &response, &result)) {
                    if (result.delegate_ip) {
                        char recv_buffer[BUFFER_SIZE];
                        ssize_t response_size;

                        /* Resolve recursively */
                        printf ("Send a recursive DNS query to %s\n", result.delegate_ip);
                        memset(&delegate_addr, 0, sizeof(server_addr));
                        delegate_addr.sin_family = AF_INET;
                        inet_pton(AF_INET, result.delegate_ip, &delegate_addr.sin_addr.s_addr);
                        delegate_addr.sin_port = htons(DNS_PORT);
                        sendto(sockfd, buffer, bytes_received, 0,
                            (struct sockaddr *)&delegate_addr, delegate_len);
                        response_size = recvfrom(sockfd, recv_buffer, BUFFER_SIZE, 0,
                            (struct sockaddr *)&delegate_addr, &delegate_len);
                        printf("Received a DNS response from %s:%d, message size: %lu\n", 
                            inet_ntoa(delegate_addr.sin_addr), ntohs(delegate_addr.sin_port), response_size); 

                        /* Handle delegation response */

                    } else {
                        /* Resolve locally */
                        printf ("Send response with the size of %lubytes\n", result.len);
                        sendto(sockfd, result.serialized, result.len, 0,
                            (struct sockaddr *)&client_addr, client_len);
                    }
                }
                break;
            // case NS:
            //     printf("Query type: NS\n");
            //     break;
            case CNAME:
                printf("Query type: CNAME\n");
                break;
            default:
                printf("Query type: Unknown\n");
                // Send not implemented response
                break;
        }
    }

    // Close socket
    close(sockfd);

    return 0;
}

