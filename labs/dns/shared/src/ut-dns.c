#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "lib/tdns/tdns-c.h"

/* A few macros that might be useful */
/* Feel free to add macros you want */
#define DNS_PORT 53
#define BUFFER_SIZE 2048 



int main() {
    /* A few variable declarations that might be useful */
    /* You can add anything you want */
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    /* PART1 TODO: Implement a DNS nameserver for the utexas.edu zone */
    
    /* 1. Create an **UDP** socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* 2. Initialize server address (INADDR_ANY, DNS_PORT) */
    /* Then bind the socket to it */
    // build address data structure
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Socket bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    /* 3. Initialize a server context using TDNSInit() */
    /* This context will be used for future TDNS library function calls */
    struct TDNSServerContext *ctx = TDNSInit();
    /* 4. Create the utexas.edu zone using TDNSCreateZone() */
    TDNSCreateZone(ctx, "utexas.edu");
    /* Add an IP address for www.utexas.edu domain using TDNSAddRecord() */
    TDNSAddRecord(ctx, "utexas.edu", "www", "40.0.0.10", NULL);
    /* Add the UTCS nameserver ns.cs.utexas.edu using using TDNSAddRecord() */
    TDNSAddRecord(ctx, "utexas.edu", "cs", NULL, "ns.cs.utexas.edu");
    /* Add an IP address for ns.cs.utexas.edu domain using TDNSAddRecord() */
    TDNSAddRecord(ctx, "cs.utexas.edu", "ns", "50.0.0.30", NULL);
    /* 5. Receive a message continuously and parse it using TDNSParseMsg() */
    struct TDNSParseResult *parsed = malloc(sizeof(struct TDNSParseResult));
    struct TDNSFindResult *ret = malloc(sizeof(struct TDNSFindResult));
    while(1) {
        uint64_t size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
        if (size == -1) {
            perror("Error receiving message");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        uint8_t res = TDNSParseMsg(buffer, size, parsed);
        if (res == 0) {
            /* 6. If it is a query for A, AAAA, NS DNS record */
            /* find the corresponding record using TDNSFind() and send the response back */
            if (TDNSFind(ctx, parsed, ret) == 1) {
                // found a record
                sendto(sockfd, ret->serialized, ret->len, 0, (struct sockaddr*)&client_addr, client_len);
            } else {
                // TDNSFind failed
                sendto(sockfd, ret->serialized, ret->len, 0, (struct sockaddr*)&client_addr, client_len);
            }
        }
        /* Otherwise, just ignore it. */
    }
    close(sockfd);
    return 0;
}

