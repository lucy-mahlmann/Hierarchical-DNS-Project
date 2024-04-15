#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "lib/tdns/tdns-c.h"

/* DNS header structure */
struct dnsheader {
        uint16_t        id;         /* query identification number */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritative answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        rcode :4;       /* response code */
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ 
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritative answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        uint16_t        qdcount;    /* number of question records */
        uint16_t        ancount;    /* number of answer records */
        uint16_t        nscount;    /* number of authority records */
        uint16_t        arcount;    /* number of resource records */
};

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

    /* PART2 TODO: Implement a local iterative DNS server */
    
    /* 1. Create an **UDP** socket */

    /* 2. Initialize server address (INADDR_ANY, DNS_PORT) */
    /* Then bind the socket to it */

    /* 3. Initialize a server context using TDNSInit() */
    /* This context will be used for future TDNS library function calls */

    /* 4. Create the edu zone using TDNSCreateZone() */
    /* Add the UT nameserver ns.utexas.edu using using TDNSAddRecord() */
    /* Add an IP address for ns.utexas.edu domain using TDNSAddRecord() */

    /* 5. Receive a message continuously and parse it using TDNSParseMsg() */

    /* 6. If it is a query for A, AAAA, NS DNS record, find the queried record using TDNSFind() */
    /* You can ignore the other types of queries */

        /* a. If the record is found and the record indicates delegation, */
        /* send an iterative query to the corresponding nameserver */
        /* You should store a per-query context using putAddrQID() and putNSQID() */
        /* for future response handling */

        /* b. If the record is found and the record doesn't indicate delegation, */
        /* send a response back */

        /* c. If the record is not found, send a response back */

    /* 7. If the message is an authoritative response (i.e., it contains an answer), */
    /* add the NS information to the response and send it to the original client */
    /* You can retrieve the NS and client address information for the response using */
    /* getNSbyQID() and getAddrbyQID() */
    /* You can add the NS information to the response using TDNSPutNStoMessage() */
    /* Delete a per-query context using delAddrQID() and putNSQID() */

    /* 7-1. If the message is a non-authoritative response */
    /* (i.e., it contains referral to another nameserver) */
    /* send an iterative query to the corresponding nameserver */
    /* You can extract the query from the response using TDNSGetIterQuery() */
    /* You should update a per-query context using putNSQID() */

    return 0;
}

