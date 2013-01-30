/*
 * Definitions for IPv6 protocol implementation
 */

////
// Constants
////

#define IPV6_ADDRESS_SIZE	16
#define IPV6_STRING_MAX		48

#define	IPV6_VERSION		0x06
#define	IPV6_DEFAULT_HOP_COUNT	0x30

#define	IPV6_HEADER_HOPBYHOP		0x00
#define	IPV6_HEADER_ROUTAGE		0x2b
#define	IPV6_HEADER_FRAGMENT		0x2c
#define	IPV6_HEADER_AUTHENTICATION	0x33
#define	IPV6_HEADER_ENCRYPTION		0x32
#define	IPV6_HEADER_DESTINATION		0x3c
#define	IPV6_HEADER_MOBILITY		0x87
#define	IPV6_HEADER_END			0x3b

#define IPV6_PROTOCOL_RAW	0xff
#define IPV6_PROTOCOL_ICMP	0x3a
#define IPV6_PROTOCOL_TCP	0x06
#define IPV6_PROTOCOL_UDP	0x11

#define	IPV6_RETRANS_MAX	5

////
// Structures
////

#pragma pack(1)

typedef struct{
  unsigned char bytes[IPV6_ADDRESS_SIZE];
  } IPv6Address;

typedef struct{
  uint32_t mixed; 
  unsigned short int length;
  unsigned char next; 
  unsigned char hop; 
  IPv6Address source;
  IPv6Address target;
  unsigned char data[1];
  } IPv6_fields;

#define IPv6_get_version(ip)	((ntohl((ip)->mixed)&0xf0000000)>>28)
#define IPv6_get_traffic(ip)	((ntohl((ip)->mixed)&0x0ff00000)>>20)
#define IPv6_get_flow(ip)	(ntohl((ip)->mixed)&0x000fffff)

#define IPv6_set_version(ip,v)	(ip)->mixed=htonl( \
				  ((v)<<28)|(ntohl((ip)->mixed)&0x0fffffff))
#define IPv6_set_traffic(ip,t)	(ip)->mixed=htonl( \
				  ((t&0xff)<<20)|(ntohl((ip)->mixed)&0xf00fffff))
#define IPv6_set_flow(ip,f)	(ip)->mixed=htonl( \
				  (f&0x000fffff)|(ntohl((ip)->mixed)&0xfff00000))

typedef struct{
  unsigned char next; 
  unsigned char length; 
  unsigned char data[1]; 
  } IPv6_header;

typedef struct{
  IPv6Address source;
  IPv6Address target;
  uint32_t length;
  uint32_t next;
  } IPv6_pseudo_header;

#pragma pack()

////
// Global variables
////

extern IPv6Address IPV6_ADDRESS_NULL;
extern IPv6Address IPV6_PREFIX_NODE;
extern IPv6Address IPV6_PREFIX_LINK;
extern IPv6Address IPV6_PREFIX_SITE;
extern IPv6Address IPV6_PREFIX_ND;
extern IPv6Address IPV6_SUFFIX_HOSTS;
extern IPv6Address IPV6_SUFFIX_ROUTERS;

////
// Prototypes
////

#ifdef VERBOSE
void displayIPv6Packet(FILE *output,IPv6_fields *ip,int size);
#endif
unsigned char ipv6Initialize(AssocArray *infos);
unsigned char ipv6DecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char ipv6SendPacket(EventsEvent *event,EventsSelector *selector);
IPv6Address ipv6Netmask(int mask);
IPv6Address ipv6Network(IPv6Address ip,int mask);
IPv6Address ipv6Broadcast(IPv6Address ip,int mask);
unsigned char ipv6Compare(IPv6Address ip1,IPv6Address ip2);
IPv6Address ipv6String2Address(char *string);
char *ipv6Address2String(IPv6Address ip);
IPv6Address ipv6Array2Address(unsigned char *array);
void ipv6Address2Array(IPv6Address ip,unsigned char *field);
unsigned short int ipv6PseudoHeaderChecksum(
  IPv6Address source,IPv6Address target,int size,int next);
