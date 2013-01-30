/*
 * Definitions for ICMPv6 protocol implementation
 */

////
// Constants
////

#define ICMPV6_TYPE_UNREACHABLE			1
#define ICMPV6_TYPE_HOP_LIMIT_EXCEEDED		3
#define ICMPV6_TYPE_BAD_PARAMETER		4

#define ICMPV6_BAD_PARAM_CODE_BAD_FIELD		0
#define ICMPV6_BAD_PARAM_CODE_UNKNOWN_HEADER	1
#define ICMPV6_BAD_PARAM_CODE_UNKNOWN_OPTION	2

#define	ICMPV6_CODE_NONE			0
#define ICMPV6_UNREACHABLE_CODE_PORT        4

#define ICMPV6_TYPE_ECHO_REQUEST		128
#define ICMPV6_TYPE_ECHO_REPLY			129

#define ICMPV6_TYPE_NEIGHBOR_SOLICITATION	135
#define ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT	136

#define ICMPV6_OPTION_TYPE_LLASOURCE		0x01
#define ICMPV6_OPTION_TYPE_LLATARGET		0x02
#define ICMPV6_OPTION_TYPE_PREFIX		0x03
#define ICMPV6_OPTION_TYPE_HEADER		0x04
#define ICMPV6_OPTION_TYPE_MTU			0x05

#define ICMPV6_LEVEL_NEIGHBOR_DISCOVERY		0x8001

////
// Structures
////

#pragma pack(1)

typedef struct{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint8_t data[1];
  } ICMPv6_fields;

typedef struct{
  uint8_t type;
  uint8_t length;
  union{
    uint8_t lla[1];
    struct {
      uint8_t length;
      uint8_t mixed;
      uint32_t vlifetime;
      uint32_t plifetime;
      uint32_t reserved;
      IPv6Address prefix;
      } s_prefix;
    struct {
      uint32_t reserved;
      uint8_t header[1];
      } s_header;
    uint32_t mtu;
    } data;
  } ICMPv6_option;

#define ICMPv6OptPrefix_get_link(opt)	((((opt)->data.s_prefix.mixed)&0x80)>>7)
#define ICMPv6OptPrefix_get_auto(opt)	((((opt)->data.s_prefix.mixed)&0x40)>>6)

#define ICMPv6OptPrefix_set_link(opt,l)	((opt)->data.s_prefix.mixed=((l)<<7)| \
					 ((opt)->data.s_prefix.mixed)&0x7f)
#define ICMPv6OptPrefix_set_auto(opt,a)	((opt)->data.s_prefix.mixed=((a)<<6)| \
					 ((opt)->data.s_prefix.mixed)&0xbf)

#pragma pack()

////
// Prototypes
////

#ifdef VERBOSE
void displayICMPv6Packet(FILE *output,ICMPv6_fields *icmp,int size);
void displayICMPv6Options(FILE *output,unsigned char *options,int size);
#endif
unsigned char icmpv6DecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char icmpv6SendPacket(EventsEvent *event,EventsSelector *selector);
