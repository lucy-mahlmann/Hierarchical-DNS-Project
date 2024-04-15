#include "comboaddress.hh"
#include "record-types.hh"
#include "swrappers.hh"
#include "sclasses.hh"
#include "dns-storage.hh"
#include <memory>
#include <fstream>
#include "tdns-c.h"

using namespace std;

/* functions for C interfaces */
namespace {

template<typename T>
struct TDNSCleanUp
{
  void operator()(vector<T*>* vec)
  {
    for(auto& p : *vec) {
      delete p;
    }
    delete vec;
  }
};
 
DNSMessageReader getDNSResponse(Socket& sock, const DNSName& dn, const DNSType& dt)
{

  DNSMessageWriter dmw(dn, dt);
  dmw.dh.rd = true;
  dmw.randomizeID();
  
  SWrite(sock, dmw.serialize());
  ComboAddress server;
  string resp =SRecvfrom(sock, 65535, server);
  
  return DNSMessageReader(resp);

}

Socket makeResolverSocket(const ComboAddress& server)
{
  Socket sock(server.sin4.sin_family, SOCK_DGRAM);
  SConnect(sock, server);
  return sock;
}

void addAdditional(const DNSNode* bestzone, const DNSName& zone, const vector<DNSName>& toresolve, DNSMessageWriter& response)
try
{
  for(auto addname : toresolve ) {
    if(!addname.makeRelative(zone)) {
      //      cout<<addname<<" is not within our zone, not doing glue"<<endl;
      continue;
    }
    DNSName wuh;
    auto addnode = bestzone->find(addname, wuh);
    if(!addnode || !addname.empty())  {
      continue;
    }
    for(auto& type : {DNSType::A, DNSType::AAAA}) {
      auto iter2 = addnode->rrsets.find(type);
      if(iter2 != addnode->rrsets.end()) {
        const auto& rrset = iter2->second;
        for(const auto& rr : rrset.contents) {
          response.putRR(DNSSection::Additional, wuh+zone, rrset.ttl, rr);
        }
      }
    }
  }  
}
catch(std::out_of_range& e) { // exceeded packet size
  cout<<"\tAdditional records would have overflowed the packet, stopped adding them, not truncating yet\n";
}


void print_str_hex (string str)
{
  for(char& c : str) {
    cout << hex << (int)c;
  }
  cout << '\n';
}

void reverse_IP (DNSName *n, string ip)
{
  string del = ".";
  int start, end = -1*del.size();
  do {
      start = end + del.size();
      end = ip.find(del, start);
      n->push_front(DNSLabel(ip.substr(start, end - start)));
  } while (end != -1);
}

}

/* C interfaces */
extern "C" {

struct TDNSServerContext
{
  DNSNode zones;
  map<string, DNSNode *> url_to_zone;
  map<uint16_t, struct sockaddr_in> qid_to_addr;
  map<uint16_t, const char *> qid_to_nsIP;
  map<uint16_t, const char *> qid_to_nsDomain;
};

struct TDNSServerContext *TDNSInit(void)
{
  auto ret = std::make_unique<TDNSServerContext>(); 
  //loadZone(ret->zones);
  return ret.release();
}

void TDNSCreateZone (struct TDNSServerContext *ctx, const char *zoneurl)
{
  DNSName zonename = makeDNSName(zoneurl);
  string zoneurl_str(zoneurl);

  auto zone = ctx->zones.add(zonename);
  auto newzone = std::make_unique<DNSNode>();
  //zonename.push_front(DNSLabel("ns"));
  //newzone->addRRs(NSGen::make(zonename));
  zone->zone = std::move(newzone);
  ctx->url_to_zone[zoneurl_str] = zone;
  cout << "Created zone named: " << zoneurl_str << endl;
}

void TDNSAddRecord(struct TDNSServerContext *ctx, const char *zoneurl, const char *subdomain, const char *IPv4, const char* NS)
{
  DNSName dn, ns;
  string zoneurl_str(zoneurl), subdomain_str(subdomain);
  dn = makeDNSName(subdomain);
  auto fnd = ctx->url_to_zone[zoneurl_str];
  if(!fnd) {
    cout << "No such zone" << zoneurl_str << endl;
  }
  cout << "Add subdomain " << dn << "to zone " << zoneurl_str <<endl;

  auto added = fnd->zone->add(dn);
  if (NS) {
    auto newzone = std::make_unique<DNSNode>();
    ns = makeDNSName(NS);
    newzone->addRRs(NSGen::make(ns));
    added->addRRs(NSGen::make(ns));
    
    added->zone = std::move(newzone);
    auto newzone_name = subdomain_str+"."+zoneurl_str;
    ctx->url_to_zone[newzone_name] = added;    
    cout << "Its NS is " << ns << endl; 
    cout << "Created zone named " << newzone_name << endl;
  }
  if (IPv4) {
    added->addRRs(AGen::make(IPv4), AAAAGen::make("::1"));
    cout << "Its IP is " << IPv4 << endl;
  } 
}
void TDNSAddPTREntry (struct TDNSServerContext *ctx, const char *zone, const char *IP, const char *domain)
{
  DNSName reverse_zone, reverse_ip_dn, domain_dn;
  string zone_str(zone), ip_str(IP);

  reverse_IP(&reverse_ip_dn, ip_str);
  domain_dn = makeDNSName(domain);

  auto fnd = ctx->url_to_zone[zone_str];
  if(!fnd) {
    cout << "No such zone" << zone_str << endl;
  }
  cout << "Add IP " << reverse_ip_dn << "to " << domain_dn << " mapping" << endl;
  auto added = fnd->zone->add(reverse_ip_dn);
  added->addRRs(PTRGen::make(domain_dn));
}

/* Parse a DNS Message, const char *message */
/* Return value: 0 if the message is a query, 1 if it's a response */
uint8_t TDNSParseMsg (const char *message, uint64_t size, struct TDNSParseResult *response)
{
  DNSName dn;
  DNSType dt;

  std::string msg(message, size);
  DNSMessageReader dmr(msg);
  dmr.getQuestion(dn, dt);

  /* set when the message contains an NS record and the nameserver's IP */
  response->nsIP = NULL;
  response->nsDomain = NULL;

  if (dmr.dh.qr == TDNS_QUERY) {
    cout << "Received a query" << endl;
    /* This is the response used in the future */
    response->dh = std::make_unique<dnsheader>().release();
    response->qname = strdup(dn.toString().c_str());
    response->qtype = (uint16_t) dt;
    response->qclass = (uint16_t) dmr.d_qclass;
    response->dh->id = dmr.dh.id;
    response->dh->rd = dmr.dh.rd;
    response->dh->ad = dmr.dh.ad;
    response->dh->ra = dmr.dh.ra;
    //response->dh->aa = dmr.dh.aa; 
    response->dh->qr = dmr.dh.qr; // this message is response
    response->dh->opcode = dmr.dh.opcode; 
    return TDNS_QUERY;
  }
  else if (dmr.dh.qr == TDNS_RESPONSE) {
    cout << "Received a response" << endl;
    response->dh = std::make_unique<dnsheader>().release();
    response->qname = strdup(dn.toString().c_str());
    response->qtype = (uint16_t) dt;
    response->qclass = (uint16_t) dmr.d_qclass;
    response->dh->id = dmr.dh.id;
    response->dh->rd = dmr.dh.rd;
    response->dh->ad = dmr.dh.ad;
    response->dh->ra = dmr.dh.ra;
    response->dh->aa = dmr.dh.aa; 
    response->dh->qr = dmr.dh.qr; 
    response->dh->opcode = dmr.dh.opcode; 
    response->dh->rcode = dmr.dh.rcode;
    response->dh->ancount = dmr.dh.ancount;
    response->dh->arcount = dmr.dh.arcount;
    response->dh->nscount = dmr.dh.nscount;
    response->dh->qdcount = dmr.dh.qdcount;
    if (response->dh->nscount > 0) {
      DNSSection rrsection;
      uint32_t rrttl;
      std::unique_ptr<RRGen> rr;
      
      while(dmr.getRR(rrsection, dn, dt, rrttl, rr)) {
        if(rrsection == DNSSection::Additional && dt == DNSType::A){
          auto agen =dynamic_cast<AGen*>(rr.get());
          cout << "Got nsIP: " << agen->toString() << endl;
          response->nsIP = strdup(agen->toString().c_str());
        }
        if (rrsection == DNSSection::Authority && dt == DNSType::NS){
          auto nsgen = dynamic_cast<NSGen*>(rr.get());
          cout << "Got NS: " << nsgen->toString() << endl;
          response->nsDomain = strdup(nsgen->toString().c_str());
        }
      }
    }
    return TDNS_RESPONSE;
  } else {
    cout << "Unknown message type" << endl;
    return 2;
  }
}

uint8_t TDNSFind (struct TDNSServerContext* context, struct TDNSParseResult *response, struct TDNSFindResult *ret)
{
  DNSName last, dn;
  const char* qname = response->qname;
  string qname_str(qname);

  dn = makeDNSName(qname);
  if (strcmp(qname, dn.toString().c_str()) != 0) {
    printf("The converted domain name doesn't match to the original one.\n");
    dn.pop_back();
  }
  ret->delegate_ip = NULL;
  response->nsIP = NULL;
  response->nsDomain = NULL;

  cout << "Looking for " << dn << endl;
  
  auto fnd = context->zones.find(dn, last);
  if(!fnd) {
    cout << "No such domain " << dn << endl;
    return false;
  }
  cout << "Found domain: " << last << endl;
  //zonename = last;
  cout << "Looking for " << dn << endl;

  if (fnd->zone) {
    auto node = fnd->zone->find(dn, last, false);
    cout << "Not matched: " << dn.toString() <<  endl;
    cout << "Matched: " << last <<  endl;

    DNSName r_qname = makeDNSName(response->qname);
    if (strcmp(qname, r_qname.toString().c_str()) != 0) {
      //printf("The converted domain name doesn't match to the original one.\n");
      r_qname.pop_back();
    } 
    //r_qname.pop_back();
    cout << "Response query name: " << r_qname << endl;
    DNSType r_qtype = (DNSType) response->qtype;
    DNSClass r_qclass = (DNSClass) response->qclass;
    
    DNSMessageWriter dmw(r_qname, r_qtype, r_qclass);
    dmw.dh.id = response->dh->id;
    dmw.dh.rd = response->dh->rd;
    dmw.dh.ad = 0;
    //dmw.dh.ra = response->dh->ra;
    dmw.dh.ra = 0;
    dmw.dh.aa = 0;
    dmw.dh.qr = TDNS_RESPONSE;
    dmw.dh.opcode = response->dh->opcode;

    string empty(".");
    // if (node->zone) {
    //   auto temp_node = node->zone->find(dn, last, false);
    //   cout << "Not matched: " << dn.toString() <<  endl;
    //   cout << "Matched: " << last <<  endl;
    // }
    
    if (node->zone && (empty.compare(dn.toString())!=0)) {
      /* check if the IP is available locally */
      auto cache_node = node->zone->find(dn, last, false);
      cout << "Not matched: " << dn.toString() <<  endl;
      cout << "Matched: " << last <<  endl;
      if (empty.compare(dn.toString())==0) {
        /* TODO: send A record */
        auto iter = cache_node->rrsets.find(r_qtype);
        auto range = make_pair(iter, iter);
        ++range.second;

        for(auto i2 = range.first; i2 != range.second; ++i2) {
          const auto& rrset = i2->second;
          for(const auto& rr : rrset.contents) {
            cout<<"Found Request Record Type: " << i2->first << endl;
            cout<<"Value: " << rr->toString() << endl;
            dmw.dh.aa=1;
            dmw.dh.rcode=0;

            dmw.putRR(DNSSection::Answer, r_qname, 3600, rr);
            
            auto serialized = dmw.serialize();
            memcpy (ret->serialized, serialized.c_str(), serialized.length());
            ret->len = serialized.length();
            return true;
          }
        }
        dmw.dh.aa=1;
        dmw.dh.rcode=(uint32_t) RCode::Nxdomain;
        auto serialized = dmw.serialize();
        memcpy (ret->serialized, serialized.c_str(), serialized.length());
        ret->len = serialized.length();
        return false;
      }

      cout << "Handle delegation." << endl;
      cout << "Zone name: " << last << endl;
      auto it = node->zone->rrsets.find(DNSType::NS);
      if (it != node->zone->rrsets.end()) {
        dmw.dh.ra = 1;
        const auto& rrset = it->second;
        vector<DNSName> toresolve;
        for(const auto& rr : rrset.contents) {
          dmw.putRR(DNSSection::Authority, last, rrset.ttl, rr);
          toresolve.push_back(dynamic_cast< NSGen* >(rr.get())->d_name);
          response->nsDomain = strdup(rr->toString().c_str());
        }

        // Add additional
        for (const DNSName &n : toresolve) {
          string full_ns_name = n.toString();
          auto pos = full_ns_name.find(last.toString());
          
          DNSName ns_subdomain = makeDNSName(full_ns_name.substr(0, pos));
          cout << "Resolve sub domain for NS: " << ns_subdomain << endl;

          auto ns_node = node->zone->find(ns_subdomain, last, false);
          
          auto i = ns_node->rrsets.find(DNSType::A);
          auto range = make_pair(i, i);
          ++range.second;
          
          for(auto i2 = range.first; i2 != range.second; ++i2) {
            const auto& rrset = i2->second;
            for(const auto& rr : rrset.contents) {
              cout<<"Found Request Record Type: " << i2->first << endl;
              cout<<"Value: " << rr->toString() << endl;      
              response->nsIP = strdup(rr->toString().c_str());
              dmw.putRR(DNSSection::Additional, n, 3600, rr);
            }
          }
        }
        auto serialized = dmw.serialize();
        memcpy (ret->serialized, serialized.c_str(), serialized.length());
        ret->len = serialized.length();
        return true;
      }
      dmw.dh.aa = 1;
      dmw.dh.rcode = (uint32_t) RCode::Nxdomain;
      auto serialized = dmw.serialize();
      memcpy (ret->serialized, serialized.c_str(), serialized.length());
      ret->len = serialized.length();
      return false;
    }

    if (empty.compare(dn.toString())==0) {
      auto iter = node->rrsets.find(r_qtype);
      if (iter == node->rrsets.end()) {
        if (node->zone) {
          //cout << "The node is zone" << endl;
          // Find there is any NS record related to the query.
          auto it = node->zone->rrsets.find(DNSType::NS);
          if (it != node->zone->rrsets.end()) {
            dmw.dh.ra = 1;
            const auto& rrset = it->second;
            vector<DNSName> toresolve;
            for(const auto& rr : rrset.contents) {
              dmw.putRR(DNSSection::Authority, last, rrset.ttl, rr);
              toresolve.push_back(dynamic_cast< NSGen* >(rr.get())->d_name);
              response->nsIP = strdup(rr->toString().c_str());
            }

            // Add additional
            for (const DNSName &n : toresolve) {
              string full_ns_name = n.toString();
              auto pos = full_ns_name.find(last.toString());
              
              DNSName ns_subdomain = makeDNSName(full_ns_name.substr(0, pos));
              cout << "Resolve sub domain for NS: " << ns_subdomain << endl;

              auto ns_node = node->zone->find(ns_subdomain, last, false);
              
              auto i = ns_node->rrsets.find(DNSType::A);
              auto range = make_pair(i, i);
              ++range.second;
              
              for(auto i2 = range.first; i2 != range.second; ++i2) {
                const auto& rrset = i2->second;
                for(const auto& rr : rrset.contents) {
                  cout<<"Found Request Record Type: " << i2->first << endl;
                  cout<<"Value: " << rr->toString() << endl;      
                  response->nsIP = strdup(rr->toString().c_str());
                  dmw.putRR(DNSSection::Additional, n, 3600, rr);
                }
              }
            }
            auto serialized = dmw.serialize();
            memcpy (ret->serialized, serialized.c_str(), serialized.length());
            ret->len = serialized.length();
            return true;
          }
        }
        cout << "Corresponding RR not found" << endl;
      }
      else {
        auto range = make_pair(iter, iter);
        ++range.second;

        for(auto i2 = range.first; i2 != range.second; ++i2) {
          const auto& rrset = i2->second;
          for(const auto& rr : rrset.contents) {
            cout<<"Found Request Record Type: " << i2->first << endl;
            cout<<"Value: " << rr->toString() << endl;
            dmw.dh.aa=1;
            dmw.dh.rcode=0;

            dmw.putRR(DNSSection::Answer, r_qname, 3600, rr);
            
            // cout<<"Response aa bit: "<<dmw.dh.aa<<", Response rcode: "<<dmw.dh.rcode<<endl;
            // cout<<"Response qr bit: "<<dmw.dh.qr<<endl;
            // cout<<"Response qdcount: "<<dmw.dh.qdcount<<endl;
            // cout<<"Response ancount: "<<dmw.dh.ancount<<endl;
            // cout<<"Response arcount: "<<dmw.dh.arcount<<endl;
            // cout<<"Response DNS header id: "<<dmw.dh.id<<endl;

            auto serialized = dmw.serialize();
            //print_str_hex(serialized);

            memcpy (ret->serialized, serialized.c_str(), serialized.length());
            ret->len = serialized.length();
            return true;
          }
        }
        cout << "Corresponding RR not found" << endl;
      }
    }
    dmw.dh.aa=1;
    dmw.dh.rcode= (uint32_t) RCode::Nxdomain;
    auto serialized = dmw.serialize();
    memcpy (ret->serialized, serialized.c_str(), serialized.length());
    ret->len = serialized.length();
  }
  return false;
}

ssize_t TDNSGetIterQuery (TDNSParseResult *response, char *serialized) {
  DNSName dn = makeDNSName(response->qname);
  DNSType dt = (DNSType) response->qtype;
  DNSClass dc = (DNSClass) response->qclass;
  DNSMessageWriter dmw(dn, dt, dc);
  dmw.dh.id = response->dh->id;
  dmw.dh.rd = 1;
  dmw.dh.ad = 0;
  dmw.dh.ra = 0;
  dmw.dh.aa = 0;
  dmw.dh.qr = TDNS_QUERY;
  dmw.dh.opcode = TDNS_QUERY;
  dmw.dh.rcode = 0;
  dmw.dh.ancount = 0;
  dmw.dh.arcount = 0;
  dmw.dh.nscount = 0;
  dmw.dh.qdcount = 1;
  string serialized_str = dmw.serialize();
  memcpy(serialized, serialized_str.c_str(), serialized_str.length());
  return serialized_str.length();
}
uint64_t TDNSPutNStoMessage (char *message, uint64_t size, TDNSParseResult *response, const char* nsIP, const char* nsDomain)
{

  DNSName dn;
  DNSType dt;  
  std::string msg(message, size);
  DNSMessageReader dmr(msg);

  DNSName r_qname = makeDNSName(response->qname);
  DNSType r_qtype = (DNSType) response->qtype;
  DNSClass r_qclass = (DNSClass) response->qclass;
  
  cout << "Response query name: " << r_qname << endl;

  DNSMessageWriter dmw(r_qname, r_qtype, r_qclass);
  dmw.dh.id = response->dh->id;
  dmw.dh.rd = response->dh->rd;
  dmw.dh.ad = response->dh->ad;
  dmw.dh.ra = response->dh->ra;
  dmw.dh.aa = response->dh->aa;
  dmw.dh.qr = response->dh->qr;
  dmw.dh.opcode = response->dh->opcode;
  dmw.dh.rcode = response->dh->rcode;
  
  DNSSection rrsection;
  uint32_t rrttl;
  std::unique_ptr<RRGen> rr;
      
  while(dmr.getRR(rrsection, dn, dt, rrttl, rr)) {
    dmw.putRR(rrsection, dn, rrttl, rr);
  }

  dmw.putRR(DNSSection::Authority, r_qname, 3600, NSGen::make(makeDNSName(nsDomain)));

  dmw.putRR(DNSSection::Additional, makeDNSName(nsDomain), 3600, AGen::make(nsIP));

  auto serialized = dmw.serialize();
  memcpy (message, serialized.c_str(), serialized.length());
  return serialized.length();
}

void putAddrQID(struct TDNSServerContext* context, uint16_t qid, struct sockaddr_in *addr)
{
  context->qid_to_addr[qid].sin_addr = addr->sin_addr;
  context->qid_to_addr[qid].sin_port = addr->sin_port;
  context->qid_to_addr[qid].sin_family = addr->sin_family;
}

void getAddrbyQID(struct TDNSServerContext* context, uint16_t qid, struct sockaddr_in *addr)
{
  addr->sin_addr = context->qid_to_addr[qid].sin_addr;
  addr->sin_port = context->qid_to_addr[qid].sin_port;
  addr->sin_family = context->qid_to_addr[qid].sin_family;
}

void delAddrQID(struct TDNSServerContext* context, uint16_t qid)
{
  context->qid_to_addr.erase(qid);
}

void putNSQID(struct TDNSServerContext* context, uint16_t qid, const char *nsIP, const char *nsDomain)
{
  if (context->qid_to_nsIP.find(qid) != context->qid_to_nsIP.end()) {
    free((char *)context->qid_to_nsIP[qid]);
  }
  if (context->qid_to_nsDomain.find(qid) != context->qid_to_nsDomain.end()) {
    free((char *)context->qid_to_nsDomain[qid]);
  }
  context->qid_to_nsIP[qid] = nsIP;
  context->qid_to_nsDomain[qid] = nsDomain;
}
void getNSbyQID(struct TDNSServerContext* context, uint16_t qid, const char **nsIP, const char **nsDomain)
{
  *nsIP = context->qid_to_nsIP[qid];
  *nsDomain = context->qid_to_nsDomain[qid];
}
void delNSQID(struct TDNSServerContext* context, uint16_t qid)
{
  if (context->qid_to_nsIP.find(qid) != context->qid_to_nsIP.end()) {
    free((char *)context->qid_to_nsIP[qid]);
    context->qid_to_nsIP.erase(qid);
  }
  if (context->qid_to_nsDomain.find(qid) != context->qid_to_nsDomain.end()) {
    free((char *)context->qid_to_nsDomain[qid]);
    context->qid_to_nsDomain.erase(qid);
  }
}
}