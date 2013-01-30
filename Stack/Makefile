#
# Makefile for virtual stack executable
#

OBJS = netether.o netarp.o netip.o netipv6.o
OBJS += neticmp.o neticmpv6.o  neticmpv6nd.o
OBJS += netudp.o nettcp.o netudpv6.o
OBJS += netroute.o
OBJS += processes.o stack.o
LIBS = -L ../Arrays -L ../Events -L ../NetTAP -larrays -levents -ltap
CFLAGS += -I ../Arrays -I ../Events -I ../NetTAP

#
# Global target
#

all: stack

#
# Cleaning target
#

clean: 
	rm -f core *.o stack

#
# Executable target
#

stack: $(OBJS)
	$(CC) -o stack $(OBJS) $(LIBS)

stack.o: stack.c netether.h netip.h netipv6.h netarp.h neticmp.h neticmpv6.h netudp.h netudpv6.h nettcp.h stack.h
netether.o: netether.c netether.h netip.h netipv6.h stack.h
netarp.o: netarp.c netether.h netip.h netipv6.h netarp.h stack.h
netip.o: netip.c netether.h netip.h netipv6.h neticmp.h stack.h
netipv6.o: netip.c netether.h netip.h netipv6.h neticmp.h stack.h
neticmp.o: neticmp.c netip.h netipv6.h neticmp.h stack.h
neticmpv6.o: neticmpv6.c netip.h netipv6.h neticmpv6.h stack.h
neticmpv6nd.o: neticmpv6nd.c netip.h netipv6.h neticmpv6.h neticmpv6nd.h stack.h
netroute.o: netroute.c netroute.h netether.h netip.h netipv6.h stack.h
nettcp.o: nettcp.c netip.h netipv6.h stack.h
netudpv6.o: netether.h netip.h netipv6.h neticmpv6.h netudpv6.h stack.h
processes.o: processes.c netip.h netipv6.h stack.h

