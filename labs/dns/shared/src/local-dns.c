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
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    /* 2. Initialize server address (INADDR_ANY, DNS_PORT) */
    /* Then bind the socket to it */
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
    /* 4. Create the edu zone using TDNSCreateZone() */
    TDNSCreateZone(ctx, "edu");
    /* Add the UT nameserver ns.utexas.edu using using TDNSAddRecord() */
    TDNSAddRecord(ctx, "edu", "utexas", NULL, "ns.utexas.edu");
    /* Add an IP address for ns.utexas.edu domain using TDNSAddRecord() */
    TDNSAddRecord(ctx, "utexas.edu", "ns", "40.0.0.20", NULL);

    /* 5. Receive a message continuously and parse it using TDNSParseMsg() */
    struct TDNSParseResult *parsed = malloc(sizeof(struct TDNSParseResult));
    struct TDNSFindResult *ret = malloc(sizeof(struct TDNSFindResult));
    struct sockaddr_in iter_query_addr;
    socklen_t query_len = sizeof(iter_query_addr);
    uint64_t size;
    // 1 if receiving response from an interative query, 0 otherwise
    int iterative_query = 0;
    struct TDNSServerContext *per_query_ctx = TDNSInit();
    while(1) {
        if (iterative_query) {
            size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&iter_query_addr, &query_len);
        } else {
            size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
        }
        if (size == -1) {
            perror("Error receiving message");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        uint8_t res = TDNSParseMsg(buffer, size, parsed);
        if (res == 0) {
            /* 6. If it is a query for A, AAAA, NS DNS record, find the queried record using TDNSFind() */
            /* You can ignore the other types of queries */
			if (TDNSFind(ctx, parsed, ret) == 1) { // found a record
				if (parsed->nsIP != NULL && parsed->nsDomain != NULL) {
					/* a. If the record is found and the record indicates delegation, */
            		/* send an iterative query to the corresponding nameserver */
            		/* You should store a per-query context using putAddrQID() and putNSQID() */
            		/* for future response handling */
                    iterative_query = 1;
                    // set address to send iterative query to
                    memset(&iter_query_addr, 0, sizeof(server_addr));
                    iter_query_addr.sin_family = AF_INET;
                    inet_pton(AF_INET, parsed->nsIP, &iter_query_addr.sin_addr.s_addr);
                    iter_query_addr.sin_port = htons(DNS_PORT);
                    putAddrQID(per_query_ctx, parsed->dh->id, &iter_query_addr);
					putNSQID(per_query_ctx, parsed->dh->id, parsed->nsIP, parsed->nsDomain);
                    // send iterative query
                    sendto(sockfd, buffer, size, 0, (struct sockaddr *)&iter_query_addr, query_len);	
				} else {
					/* b. If the record is found and the record doesn't indicate delegation, */
            		/* send a response back */
                    iterative_query = 0;
					sendto(sockfd, ret->serialized, ret->len, 0, (struct sockaddr*)&client_addr, client_len);
				}	
            } else {
				/* c. If the record is not found, send a response back */
                iterative_query = 0;
				sendto(sockfd, ret->serialized, ret->len, 0, (struct sockaddr*)&client_addr, client_len);
			}  
        } else {
            // parsed message is a response
			if (parsed->nsIP == NULL && parsed->nsDomain == NULL) {
				/* 7. If the message is an authoritative response (i.e., it contains an answer), */
				/* add the NS information to the response and send it to the original client */
				/* You can retrieve the NS and client address information for the response using */
				/* getNSbyQID() and getAddrbyQID() */
				/* You can add the NS information to the response using TDNSPutNStoMessage() */
				/* Delete a per-query context using delAddrQID() and putNSQID() */
                iterative_query = 0;
                memset(&iter_query_addr, 0, sizeof(server_addr));
				getNSbyQID(per_query_ctx, parsed->dh->id, &(parsed->nsIP), &(parsed->nsDomain));
				getAddrbyQID(per_query_ctx, parsed->dh->id, &iter_query_addr);
				uint16_t newLen = TDNSPutNStoMessage(buffer, size, parsed, parsed->nsIP, parsed->nsDomain);
				// send response to original client
				sendto(sockfd, buffer, newLen, 0, (struct sockaddr*)&client_addr, client_len);
				delAddrQID(per_query_ctx, parsed->dh->id);
				delNSQID(per_query_ctx, parsed->dh->id);
			} else {
				/* 7-1. If the message is a non-authoritative response */
				/* (i.e., it contains referral to another nameserver) */
				/* send an iterative query to the corresponding nameserver */
				/* You can extract the query from the response using TDNSGetIterQuery() */
				/* You should update a per-query context using putNSQID() */
                iterative_query = 1;
				ssize_t querySize = TDNSGetIterQuery(parsed, ret->serialized);
				ret->len = querySize;
				putNSQID(per_query_ctx, parsed->dh->id, parsed->nsIP, parsed->nsDomain);
                // set the address to send the iterative query to
                memset(&iter_query_addr, 0, sizeof(server_addr));
                iter_query_addr.sin_family = AF_INET;
                inet_pton(AF_INET, parsed->nsIP, &iter_query_addr.sin_addr.s_addr);
                iter_query_addr.sin_port = htons(DNS_PORT);
                // send iterative query
                sendto(sockfd, ret->serialized, ret->len, 0, (struct sockaddr*)&iter_query_addr, query_len);
			}
        }
    }
    close(sockfd);
    return 0;
}

