TDNSDIR:=./src/lib/tdns
CXXFLAGS:=-std=gnu++14 -Werror -O2 -MMD -MP -ggdb -I$(TDNSDIR)/ext/simplesocket -I$(TDNSDIR)/ext/simplesocket/ext/fmt-5.2.1/include -I$(TDNSDIR)/ext/ -pthread 
CFLAGS:= -Wall -O2 -MMD -MP -ggdb 
SRCDIR:=./src
BINDIR:=./bin

PROGRAMS = ut-dns cs-dns local-dns

all: $(PROGRAMS)

clean:
	rm -f $(SRCDIR)/*.o $(SRCDIR)/*.d $(BINDIR)/*

check: testrunner tauth tdig 
	./testrunner
	cd tests ; ./basic

-include $(TDNSDIR)/*.d

SIMPLESOCKET = $(TDNSDIR)/ext/simplesocket/comboaddress.o $(TDNSDIR)/ext/simplesocket/sclasses.o $(TDNSDIR)/ext/simplesocket/swrappers.o $(TDNSDIR)/ext/simplesocket/ext/fmt-5.2.1/src/format.o

ut-dns.o: $(SRCDIR)/ut-dns.c
	$(CXX) -std=gnu++14 $^ -c $(SRCDIR)/$@
ut-dns: $(SRCDIR)/ut-dns.o $(TDNSDIR)/tdns-c.o $(TDNSDIR)/record-types.o $(TDNSDIR)/dns-storage.o $(TDNSDIR)/dnsmessages.o $(SIMPLESOCKET)
	$(CXX) -std=gnu++14 $^ -o $(BINDIR)/$@ 
cs-dns.o: $(SRCDIR)/cs-dns.c
	$(CXX) -std=gnu++14 $^ -c $(SRCDIR)/$@
cs-dns: $(SRCDIR)/cs-dns.o $(TDNSDIR)/tdns-c.o $(TDNSDIR)/record-types.o $(TDNSDIR)/dns-storage.o $(TDNSDIR)/dnsmessages.o $(SIMPLESOCKET)
	$(CXX) -std=gnu++14 $^ -o $(BINDIR)/$@ 
local-dns.o: $(SRCDIR)/local-dns.c
	$(CXX) -std=gnu++14 $^ -c $(SRCDIR)/$@
local-dns: $(SRCDIR)/local-dns.o $(TDNSDIR)/tdns-c.o $(TDNSDIR)/record-types.o $(TDNSDIR)/dns-storage.o $(TDNSDIR)/dnsmessages.o $(SIMPLESOCKET)
	$(CXX) -std=gnu++14 $^ -o $(BINDIR)/$@