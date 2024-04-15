#ifndef TDNS_TDNS_H
#define TDNS_TDNS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Macros */
#define MAX_RESPONSE 2048

#define TDNS_QUERY 0
#define TDNS_RESPONSE 1

enum TDNSType
{
  A = 1, NS = 2, CNAME = 5, SOA=6, PTR=12, MX=15, TXT=16, AAAA = 28, SRV=33, NAPTR=35, DS=43, RRSIG=46,
  NSEC=47, DNSKEY=48, NSEC3=50, OPT=41, IXFR = 251, AXFR = 252, ANY = 255, CAA = 257
};


/* Server-wide context */
/* Maintains DNS records in a hierarchical manner */
/* and per-query contexts for handling iterative queries */
/* In the assignment, the server can contain only two kinds of records. */
/* One contains IP address, and the other points to another nameserver */
struct TDNSServerContext;


/* Result for TDNSParseMsg */
struct TDNSParseResult {
  struct dnsheader *dh; /* parsed dnsheader, you need this in Part 2 */
  uint16_t qtype; /* query type, the value should be one of enum TDNSType values */
  const char *qname; /* query name (i.e. domain name for A type query) */
  uint16_t qclass; /* query class */

  /* Below are for handling a referral response (delegation). */ 
  /* These should be NULL if it's not a referral response */
  const char *nsIP;  /* an IP address to the nameserver */
  const char *nsDomain; /* an IP address to the nameserver */
};

/* Result for TDNSFind function */
struct TDNSFindResult {
  char serialized[MAX_RESPONSE]; /* a DNS response string based on the search result */
  ssize_t len; /* the response string's length */
  
  /* Below is for delegation */
  const char *delegate_ip; /* IP to the nameserver to which a server delegates a query */
};

/************************/
/* For both Part 1 and 2*/
/************************/

/* Initializes the server context and returns a pointer to the server context */
/* This context will be used for future TDNS library function calls */
struct TDNSServerContext *TDNSInit(void);

/* Creates a zone for the given domain, zoneurl */
/* e.g., TDNSCreateZone(ctx, "google.com") */
void TDNSCreateZone (struct TDNSServerContext *ctx, const char *zoneurl);
/* Adds either an NS record or A record for the subdomain in the zone */
/* A record example*/
/* e.g., TDNSAddRecord(ctx, "google.com", "www", "123.123.123.123", NULL) */
/* Below will also implicitly create a maps.google.com zone */
/* e.g., TDNSAddRecord(ctx, "google.com", "maps", NULL, "ns.maps.google.com")*/
/* Then you can add an IP for ns.maps.google.com like below */
/* e.g., TDNSAddRecord(ctx, "maps.google.com", "ns", "111.111.111.111", NULL)*/
void TDNSAddRecord (struct TDNSServerContext *ctx, const char *zoneurl, const char *subdomain, const char *IPv4, const char* NS);

/* Parses a DNS message and stores the result in `parsed` */
/* Returns 0 if the message is a query, 1 if it's a response */
/* Note: Don't forget to specify the size of the message! */
/* If the message is a referral response, parsed->nsIP and parsed->nsDomain will contain */
/* the IP address and domain name for the referred nameserver */
uint8_t TDNSParseMsg (const char *message, uint64_t size, struct TDNSParseResult *parsed);

/* Finds a DNS record for the query represented by `parsed` and stores the result in `result`*/
/* Returns 0 if it fails to find a corresponding record */
/* Returns 1 if it finds a corresponding record */
/* If the record indicates delegation, result->delegate_ip will store */
/* the IP address to which it delegates the query */uint8_t TDNSFind (struct TDNSServerContext* context, struct TDNSParseResult *parsed, struct TDNSFindResult *result);

/**************/
/* for Part 2 */
/**************/

/* Extracts a query from a parsed DNS message and stores it in serialized */
/* Returns size of the serialized query in bytes. */
/* This is useful when you extract a query from a referral response. */
ssize_t TDNSGetIterQuery(struct TDNSParseResult *parsed, char *serialized);

/* Puts NS information to a DNS message */
/* messeage will be updated and the updated length will be returned. */
/* This should be used when you get the final answer from a nameserver */
/* to let a client know the trajectory. */
uint64_t TDNSPutNStoMessage (char *message, uint64_t size, struct TDNSParseResult *parsed, const char* nsIP, const char* nsDomain);

/* For maintaining per-query contexts */
void putAddrQID(struct TDNSServerContext* context, uint16_t qid, struct sockaddr_in *addr);
void getAddrbyQID(struct TDNSServerContext* context, uint16_t qid, struct sockaddr_in *addr);
void delAddrQID(struct TDNSServerContext* context, uint16_t qid);
void putNSQID(struct TDNSServerContext* context, uint16_t qid, const char *nsIP, const char *nsDomain);
void getNSbyQID(struct TDNSServerContext* context, uint16_t qid, const char **nsIP, const char **nsDomain);
void delNSQID(struct TDNSServerContext* context, uint16_t qid);

/* unused */
void TDNSAddPTREntry (struct TDNSServerContext *ctx, const char *zone, const char *IP, const char *domain);

#ifdef __cplusplus
}
#endif

  
#endif
