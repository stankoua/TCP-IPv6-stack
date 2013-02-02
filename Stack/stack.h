/*
 * Definitions for virtual stack
 */

////
// Constants
////

#define INTERFACE_TYPE_ETHERNET	0

#define LEVEL_LINK                  0x0002  // 2
#define LEVEL_ARESOL_IPV4           0x0012  // 18
#define LEVEL_NETWORK               0x0003  // 3
#define LEVEL_CONTROL_IPV4          0x0014  // 20
#define LEVEL_CONTROL_IPV6	        0x0024  // 36
#define LEVEL_TRANSPORT		        0x0004  // 4
#define LEVEL_TRANSPORT_IPV6		0x002C  // 44

#define MATADDR_ETHERNET	0
#define LOGADDR_IPV4		0
#define LOGADDR_IPV6		1

#define PROCESS_INIT		0
#define PROCESS_DATA		1
#define PROCESS_CONNECT		2
#define PROCESS_CLOSE		3

////
// Structures
////

typedef struct{
  EthernetAddress *addresses;
  int allocated;
  int size;
  } EthernetMulticastAddresses;

typedef struct{
  IPv4Address address;
  int netmask;
  } NetworkAddressesIPv4;

typedef struct{
  IPv6Address address;
  int netmask;
  } NetworkAddressesIPv6;

typedef struct{
  IPv6Address *addresses;
  int allocated;
  int size;
  } IPv6MulticastAddresses;

typedef struct{
  int identity;
  int type;
  int descriptor;
  char name_int[ETHERNET_NAME_MAX_SIZE];
  char name_tap[ETHERNET_NAME_MAX_SIZE];
  EthernetAddress ether_addr;
  EthernetMulticastAddresses *ether_multicast;
  NetworkAddressesIPv4 *IPv4;
  NetworkAddressesIPv6 *IPv6;
  IPv6MulticastAddresses *IPv6_multicast;
  } EthernetInterface;

typedef struct{
  int identity;
  int type;
  char padding[1];
  } GenericInterface;

typedef struct{
  int material;
  int logical;
  unsigned char (*function)(void *logical,void *material);
  } AddressResolutionModule;

typedef struct{
  int identity;
  int level;
  int protocol;
  unsigned char (*initialize)(AssocArray *infos);
  unsigned char (*action_in)(EventsEvent *,EventsSelector *);
  unsigned char (*action_out)(EventsEvent *,EventsSelector *);
  int event_in;
  int event_out;
  } StackLayers;

typedef struct{
  IPv4Address address;
  unsigned short int port;
  } SocketAddress;

typedef struct{
  unsigned char protocol;
  IPv4Address address;
  short int port;
  unsigned char (*process)(
    unsigned char type,
    SocketAddress to,SocketAddress from,
    unsigned char *data,int size);
  int event;
  } StackProcess;

typedef struct{
  unsigned char protocol;
  IPv6Address addressv6;
  short int port;
  unsigned char (*process)(
    unsigned char type,
    SocketAddress to,SocketAddress from,
    unsigned char *data,int size);
  int event;
  } StackProcessv6;
////
// Prototypes
////

unsigned char stackAddEthernetMulticast(
  EthernetMulticastAddresses *multicast,EthernetAddress new);
unsigned char stackDelEthernetMulticast(
  EthernetMulticastAddresses *multicast,EthernetAddress del);
unsigned char stackFindEthernetMulticast(
  EthernetMulticastAddresses *multicast,EthernetAddress address);
unsigned char stackAddIPv6Multicast(
  IPv6MulticastAddresses *multicast,IPv6Address new);
unsigned char stackDelIPv6Multicast(
  IPv6MulticastAddresses *multicast,IPv6Address del);
unsigned char stackFindIPv6Multicast(
  IPv6MulticastAddresses *multicast,IPv6Address address);
GenericInterface *stackFindDeviceByIdentity(int identity);
EthernetInterface *stackFindEthernetDeviceByAddr(EthernetAddress src);
EthernetInterface *stackFindEthernetDeviceByName(char *name);
EthernetInterface *stackFindEthernetDeviceByIPv4(IPv4Address ip);
EthernetInterface *stackFindEthernetDeviceByIPv4Broadcast(IPv4Address ip);
EthernetInterface *stackFindEthernetDeviceByIPv4Network(IPv4Address ip);
EthernetInterface *stackFindEthernetDeviceByIPv6(IPv6Address ip);
EthernetInterface *stackFindEthernetDeviceByIPv6Multicast(IPv6Address mcast);
EthernetInterface *stackFindEthernetDeviceByIPv6Network(IPv6Address ip);
void stackDisplayDevices(FILE *output);
StackLayers *stackFindLayerByProtocol(int level,int protocol);
StackLayers *stackFindLayerByIdentity(int identity);
unsigned short int genericChecksum(unsigned char *bytes,int size,int init);
unsigned char stackAddressResolution(int mtype,int ltype,void *maddr,void *laddr);
StackProcess *stackFindProcess(
  unsigned char protocol,IPv4Address address,short int port);
StackProcess *stackFindProcessIpv6(
  unsigned char protocol,IPv6Address address,short int port);
unsigned char stackUDPSendDatagram(
  IPv4Address to_ip,unsigned short int to_port,unsigned char *data,int size);
unsigned char stackUDPv6SendDatagram(
  IPv6Address to_ip,unsigned short int to_port,unsigned char *data,int size);
unsigned char stackTCPSendData(
  IPv4Address to_ip,unsigned short int to_port,
  unsigned char type,unsigned char *data,int size);

void *_realloc(void *ptr, size_t size);
