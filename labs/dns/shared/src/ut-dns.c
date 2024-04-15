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

    /* 2. Initialize server address (INADDR_ANY, DNS_PORT) */
    /* Then bind the socket to it */

    /* 3. Initialize a server context using TDNSInit() */
    /* This context will be used for future TDNS library function calls */

    /* 4. Create the utexas.edu zone using TDNSCreateZone() */
    /* Add an IP address for www.utexas.edu domain using TDNSAddRecord() */
    /* Add the UTCS nameserver ns.cs.utexas.edu using using TDNSAddRecord() */
    /* Add an IP address for ns.cs.utexas.edu domain using TDNSAddRecord() */

    /* 5. Receive a message continuously and parse it using TDNSParseMsg() */

    /* 6. If it is a query for A, AAAA, NS DNS record */
    /* find the corresponding record using TDNSFind() and send the response back */
    /* Otherwise, just ignore it. */

    return 0;
}

