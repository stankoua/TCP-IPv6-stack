/*
 * Definitions for ICMPv6 ND protocol implementation
 */

////
// Constants
////

#define ND_ENTRY_DYNAMIC	0
#define ND_ENTRY_STATIC		1

#define ND_ANSWER_TIMEOUT	100000
#define ND_CACHE_TIMEOUT	120

////
// Structures
////

#pragma pack(1)

typedef struct{
  uint32_t reserved;
  IPv6Address target;
  uint8_t options[1];
  } ICMPv6NDsol_fields;

typedef struct{
  uint32_t mixed;
  IPv6Address target;
  uint8_t options[1];
  } ICMPv6NDadv_fields;

#define ICMPv6ND_get_router(nd)		((ntohl((nd)->mixed)&0x80000000)>>31)
#define ICMPv6ND_get_solicited(nd)	((ntohl((nd)->mixed)&0x40000000)>>30)
#define ICMPv6ND_get_override(nd)	((ntohl((nd)->mixed)&0x20000000)>>29)

#define IPv6_get_traffic(ip)    ((ntohl((ip)->mixed)&0x0ff00000)>>20)
#define IPv6_get_flow(ip)       (ntohl((ip)->mixed)&0x000fffff)

#define ICMPv6ND_set_router(nd,r)	(nd)->mixed=htonl( \
                        	          ((r)<<31)|(ntohl((nd)->mixed)&0x7fffffff))
#define ICMPv6ND_set_solicited(nd,s)	(nd)->mixed=htonl( \
                        	          ((s)<<30)|(ntohl((nd)->mixed)&0xbfffffff))
#define ICMPv6ND_set_override(nd,o)	(nd)->mixed=htonl( \
                        	          ((o)<<29)|(ntohl((nd)->mixed)&0xdfffffff))

#pragma pack()

typedef struct{
  int type;
  IPv6Address ipv6;
  EthernetAddress ethernet;
  time_t timestamp;
  } ND_cache_entry;

typedef struct{
  int allocated;
  int size;
  ND_cache_entry *entries;
  } ND_cache;

////
// Prototypes
////

#ifdef VERBOSE
void displayICMPv6NDPacket(FILE *output,int type,unsigned char *nd,int size);
void icmpv6NDDisplayCache(FILE *output);
#endif
unsigned char icmpv6ndInitialize(AssocArray *infos);
unsigned char icmpv6ndDecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char icmpv6ndSendPacket(EventsEvent *event,EventsSelector *selector);
unsigned char icmpv6NDFindMaterial(void *material,void *logical);
