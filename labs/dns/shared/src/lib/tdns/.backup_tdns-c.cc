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
void loadZone(DNSNode& zones)
{

  /* Load a DNS zone for utexas.edu */
  auto zone = zones.add({"utexas", "edu"});
  
  auto newzone = std::make_unique<DNSNode>(); 
  
  //newzone->addRRs(NSGen::make({"ns1", "tdns", "powerdns", "org"}));
  newzone->add({"cs"})->addRRs(AGen::make("40.0.0.10"), AAAAGen::make("::1"));
  newzone->addRRs(AGen::make("20.0.0.10"));
  newzone->addRRs(AAAAGen::make("::1"));
  //newzone->rrsets[DNSType::AAAA].ttl= 900;


  newzone->add({"lib"})->addRRs(AGen::make("30.0.0.10"), AAAAGen::make("::1"));
  newzone->add({"canvas"})->addRRs(AGen::make("50.0.0.10"), AAAAGen::make("::1"));
 
  // newzone->add({"*", "nl"})->rrsets[DNSType::A].add(AGen::make("5.6.7.8"));
  // newzone->add({"*", "fr"})->rrsets[DNSType::CNAME].add(CNAMEGen::make({"server2", "tdns", "powerdns", "org"}));

  // newzone->add({"fra"})->addRRs(NSGen::make({"ns1","fra","powerdns","org"}), NSGen::make({"ns1","fra","powerdns","org"}));
  // newzone->add({"ns1"})->addRRs(AGen::make("52.56.155.186"));
  // newzone->add({"ns1", "fra"})->addRRs(AGen::make("12.13.14.15"));
  // newzone->add({"NS2", "fra"})->addRRs(AGen::make("12.13.14.16"));
  // newzone->add({"ns2", "fra"})->addRRs(AAAAGen::make("::1"));  
  zone->zone = std::move(newzone);
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
};

struct TDNSServerContext *TDNSInitAuth(void)
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

void TDNSAddEntry(struct TDNSServerContext *ctx, const char *zoneurl, const char *subdomain, const char *IPv4, const char* NS)
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

/* For authoritative server */
struct TDNSQuery * TDNSParseQuery (const char *message, uint64_t size, struct TDNSResponse *response)
{
  auto ret = std::make_unique<TDNSQuery>();
  DNSName dn;
  DNSType dt;
  std::string query(message, size);
  ostringstream qname_ss;
  //cout << "Query: " << query << endl;

  DNSMessageReader dmr(query);
  dmr.getQuestion(dn, dt);
  qname_ss << dn << endl;
  cout<<"Received a query with qname " <<dn<<", qtype "<<dt<<endl;
  cout<<"DNS header ID: "<<dmr.dh.id<<endl;
  ret->qname = strdup(qname_ss.str().c_str());
  ret->qtype = (uint16_t) dt;

  response->dh = std::make_unique<dnsheader>().release();
  response->qname = ret->qname;
  response->qtype = (uint16_t) dt;
  response->qclass = (uint16_t) dmr.d_qclass;
  response->dh->id = dmr.dh.id;
  response->dh->rd = dmr.dh.rd;
  response->dh->ad = response->dh->ra = 0;
  response->dh->aa = 0; // this message is authoritative answer.
  response->dh->qr = 1; // this message is response
  response->dh->opcode = dmr.dh.opcode; 

  return ret.release();
}

/* Parse a DNS Message, const char *message */
/* Return value: 0 if the message is a query, 1 if it's a response */
uint8_t TDNSParseMsg (const char *message, uint64_t size, struct TDNSQuery *query, struct TDNSResponse *response)
{
  DNSName dn;
  DNSType dt;

  std::string msg(message, size);
  DNSMessageReader dmr(msg);
  dmr.getQuestion(dn, dt);

  if (dmr.dh.qr == TDNS_QUERY) {
    cout << "Received a query" << endl;
    query->qname = strdup(dn.toString().c_str());
    query->qtype = (uint16_t) dt;
    response->dh = std::make_unique<dnsheader>().release();
    response->qname = query->qname;
    response->qtype = (uint16_t) dt;
    response->qclass = (uint16_t) dmr.d_qclass;
    response->dh->id = dmr.dh.id;
    response->dh->rd = dmr.dh.rd;
    response->dh->ad = response->dh->ra = 0;
    response->dh->aa = 0; 
    response->dh->qr = 1; // this message is response
    response->dh->opcode = dmr.dh.opcode; 
    return TDNS_QUERY;
  }
  else if (dmr.dh.qr == TDNS_RESPONSE) {
    cout << "Received a response" << endl;
    return TDNS_RESPONSE;
  } else {
    cout << "Unknown message type" << endl;
    return 2;
  }
}

uint8_t TDNSFind (struct TDNSServerContext* context, const char *qname, struct TDNSResponse *response, struct TDNSFindResult *ret)
{
  DNSName last, dn;
  string qname_str(qname);

  dn = makeDNSName(qname);
  if (strcmp(qname, dn.toString().c_str()) != 0) {
    printf("The converted domain name doesn't match to the original one.\n");
    dn.pop_back();
  }
  ret->delegate_ip = NULL;
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
      printf("The converted domain name doesn't match to the original one.\n");
      r_qname.pop_back();
    } 
    //r_qname.pop_back();
    cout << "Response query name: " << r_qname << endl;
    DNSType r_qtype = (DNSType) response->qtype;
    DNSClass r_qclass = (DNSClass) response->qclass;
    
    DNSMessageWriter dmw(r_qname, r_qtype, r_qclass);
    dmw.dh.id = response->dh->id;
    dmw.dh.rd = response->dh->rd;
    dmw.dh.ad = response->dh->ad;
    dmw.dh.ra = response->dh->ra;
    dmw.dh.aa = response->dh->aa;
    dmw.dh.qr = response->dh->qr;
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
              ret->delegate_ip = strdup(rr->toString().c_str());
              dmw.putRR(DNSSection::Additional, n, 3600, rr);
            }
          }
        }
        auto serialized = dmw.serialize();
        memcpy (ret->serialized, serialized.c_str(), serialized.length());
        ret->len = serialized.length();
        return true;
      }
      return false;
    }


    auto iter = node->rrsets.find(r_qtype);
    if (iter == node->rrsets.end()) {
      cout << "Zone name: " << last << endl;
      if (node->zone == NULL && fnd->zone != NULL) {
        node = fnd;
      } else if (node->zone == NULL && fnd->zone == NULL) {
        cout << "No such domain " << dn << endl;
        return false;
      }
      auto it = node->zone->rrsets.find(DNSType::NS);
      if (it != node->zone->rrsets.end()) {
        cout << "NS record found" << endl;
        dmw.dh.ra = 1;
        const auto& rrset = it->second;
        vector<DNSName> toresolve;
        for(const auto& rr : rrset.contents) {
          dmw.putRR(DNSSection::Authority, last, rrset.ttl, rr);
          toresolve.push_back(dynamic_cast< NSGen* >(rr.get())->d_name);
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
              ret->delegate_ip = strdup(rr->toString().c_str());
              dmw.putRR(DNSSection::Additional, n, 3600, rr);
            }
          }
        }
        auto serialized = dmw.serialize();
        memcpy (ret->serialized, serialized.c_str(), serialized.length());
        ret->len = serialized.length();
        return true;
      }
      else {
        cout << "Corresponding RR not found" << endl;
        return false;
      }
    }
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
        cout << "hello3" << endl;
        return true;
      }
    }
    cout << "Corresponding RR not found" << endl;
  }
  cout << "hello2" << endl;
  return false;
}

/* For resovler */
struct TDNSContext
{
  std::vector<ComboAddress> servers;
};

struct TDNSContext* TDNSMakeContext (const char* servers)
{
  auto ret = std::make_unique<TDNSContext>();

  if(!servers || !*servers) {
    ifstream ifs("/etc/resolv.conf");

    if(!ifs) 
      return 0;
    string line;    
    while(std::getline(ifs, line)) {
      auto pos = line.find_last_not_of(" \r\n\x1a");
      if(pos != string::npos)
        line.resize(pos+1);
      pos = line.find_first_not_of(" \t");
      if(pos != string::npos)
        line = line.substr(pos);

      pos = line.find_first_of(";#");
      if(pos != string::npos)
        line.resize(pos);
      
      if(line.rfind("nameserver ", 0)==0 || line.rfind("nameserver\t", 0) == 0) {
        pos = line.find_first_not_of(" ", 11);
        if(pos != string::npos) {
          try {
            ret->servers.push_back(ComboAddress(line.substr(pos), 53));
          }
          catch(...)
            {}
        }
      }
    }
  }
  else {
    ret->servers.push_back(ComboAddress(servers, 53));
  }
  if(ret->servers.empty()) {
    return 0;
  }
  return ret.release();
}

void freeTDNSContext(struct TDNSContext* tdc)
{
  delete tdc;
}
const char* TDNSErrorMessage(int err)
{
  static const char *errors[]={"No error", "Timeout", "Server failure", "No such domain", "Unknown error"};
  static constexpr int size = sizeof(errors)/sizeof(errors[0]);

  if(err >= size)
    err = size-1; 
  return errors[err];
};


void freeTDNSIPAddresses(struct TDNSIPAddresses*vec)
{
  auto ptr = (vector<struct sockaddr_storage*>*) vec->__handle;
  TDNSCleanUp<struct sockaddr_storage>()(ptr);
  delete vec;
}

int TDNSLookupIPs(TDNSContext* context, const char* name, int timeoutMsec, int lookupIPv4, int lookupIPv6,  struct TDNSIPAddresses** ret)
{
  Socket sock = makeResolverSocket(context->servers[0]);
  vector<DNSType> dtypes;
  if(lookupIPv4)
    dtypes.push_back(DNSType::A);
  if(lookupIPv6)
    dtypes.push_back(DNSType::AAAA);
  DNSName dn = makeDNSName(name);

  std::unique_ptr<vector<struct sockaddr_storage*>, TDNSCleanUp<struct sockaddr_storage>> sas(new vector<struct sockaddr_storage*>());
  uint32_t resttl = std::numeric_limits<uint32_t>::max();
  
  for(const auto& dt : dtypes) {
    DNSMessageReader dmr = getDNSResponse(sock, dn, dt);
    DNSName rrdn;
    DNSType rrdt;

    dmr.getQuestion(rrdn, rrdt);
    if(dmr.dh.rcode) {
      return 3; 
    }
    //    cout<<"Received response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<rrdn<<", qtype "<<rrdt<<endl;
      
    std::unique_ptr<RRGen> rr;


    DNSSection rrsection;
    uint32_t rrttl;
    
    while(dmr.getRR(rrsection, rrdn, rrdt, rrttl, rr)) {
      if(rrttl < resttl)
        resttl = rrttl;
      //      cout << rrsection << " " << rrdn<< " IN " << rrdt << " " << rrttl << " " <<rr->toString()<<endl;
      if(rrsection != DNSSection::Answer || rrdt != dt)
        continue;
      ComboAddress ca;
      if(dt == DNSType::A) {
        auto agen =dynamic_cast<AGen*>(rr.get());
        ca = agen->getIP();
      }
      else {
        auto agen =dynamic_cast<AAAAGen*>(rr.get());
        ca = agen->getIP();
      }
      auto sa = new struct sockaddr_storage();
      memcpy(sa, &ca, sizeof(ca));
      sas->push_back(sa);
    }
  }
  sas->push_back(0);

  *ret = new struct TDNSIPAddresses();
  (*ret)->ttl = resttl;
  (*ret)->addresses = (struct sockaddr_storage**)(&(*sas)[0]);
  (*ret)->__handle = sas.get();
  sas.release();
  return 0;
}

int TDNSLookupMXs(TDNSContext* context, const char* name, int timeoutMsec, struct TDNSMXs** ret)
{
  Socket sock = makeResolverSocket(context->servers[0]);

  std::unique_ptr<vector<struct TDNSMX*>, TDNSCleanUp<struct TDNSMX>> sas(new vector<struct TDNSMX*>());
  uint32_t resttl = std::numeric_limits<uint32_t>::max();
  DNSName dn = makeDNSName(name);
  DNSMessageReader dmr = getDNSResponse(sock, dn, DNSType::MX);
  DNSName rrdn;
  DNSType rrdt;

  dmr.getQuestion(rrdn, rrdt);
      
  //  cout<<"Received response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<rrdn<<", qtype "<<rrdt<<endl;
      
  std::unique_ptr<RRGen> rr;
  DNSSection rrsection;
  uint32_t rrttl;
  
  while(dmr.getRR(rrsection, rrdn, rrdt, rrttl, rr)) {
    if(rrttl < resttl)
      resttl = rrttl;
    //    cout << rrsection << " " << rrdn<< " IN " << rrdt << " " << rrttl << " " <<rr->toString()<<endl;
    if(rrsection != DNSSection::Answer || rrdt != DNSType::MX)
        continue;
    if(rrdt == DNSType::MX) {
        auto mxgen =dynamic_cast<MXGen*>(rr.get());
        auto sa = new struct TDNSMX();
        sa->priority = mxgen->d_prio;
        sa->name = strdup(mxgen->d_name.toString().c_str());
        sas->push_back(sa);
    }
  }
  sas->push_back(0);

  *ret = new struct TDNSMXs();
  (*ret)->ttl = resttl;
  (*ret)->mxs = (struct TDNSMX**)(&(*sas)[0]);
  (*ret)->__handle = sas.get();
  sas.release();
  return 0;
}

void freeTDNSMXs(struct TDNSMXs* vec)
{
  auto ptr = (vector<struct TDNSMX*>*) vec->__handle;
  for(auto& p : *ptr) {
    if(!p) break;
    free((void*)p->name);
    delete p;
  }
  delete ptr;
  delete vec;
}

int TDNSLookupTXTs(TDNSContext* context, const char* name, int timeoutMsec, struct TDNSTXTs** ret)
{
  Socket sock = makeResolverSocket(context->servers[0]);

  std::unique_ptr<vector<struct TDNSTXT*>, TDNSCleanUp<struct TDNSTXT>> sas(new vector<struct TDNSTXT*>());
  uint32_t resttl = std::numeric_limits<uint32_t>::max();
  DNSName dn = makeDNSName(name);
  DNSMessageReader dmr = getDNSResponse(sock, dn, DNSType::TXT);
  DNSName rrdn;
  DNSType rrdt;

  dmr.getQuestion(rrdn, rrdt);
      
  //  cout<<"Received response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<rrdn<<", qtype "<<rrdt<<endl;
      
  std::unique_ptr<RRGen> rr;
  DNSSection rrsection;
  uint32_t rrttl;
  
  while(dmr.getRR(rrsection, rrdn, rrdt, rrttl, rr)) {
    if(rrttl < resttl)
      resttl = rrttl;
    //    cout << rrsection << " " << rrdn<< " IN " << rrdt << " " << rrttl << " " <<rr->toString()<<endl;
    if(rrsection != DNSSection::Answer || rrdt != DNSType::TXT)
        continue;
    if(rrdt == DNSType::TXT) {
        auto txtgen =dynamic_cast<TXTGen*>(rr.get());
        auto sa = new struct TDNSTXT();
        sa->content = strdup(txtgen->toString().c_str());
        sas->push_back(sa);
    }
  }
  sas->push_back(0);

  *ret = new struct TDNSTXTs();
  (*ret)->ttl = resttl;
  (*ret)->txts = (struct TDNSTXT**)(&(*sas)[0]);
  (*ret)->__handle = sas.get();
  sas.release();
  return 0;
}

void freeTDNSTXTs(struct TDNSTXTs* vec)
{
  auto ptr = (vector<struct TDNSTXT*>*) vec->__handle;
  for(auto& p : *ptr) {
    if(!p) break;
    free((void*)p->content);
    delete p;
  }
  delete ptr;
  delete vec;
}
  
  
}
