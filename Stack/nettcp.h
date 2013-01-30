/*
 * Definitions for TCP protocol implementation
 */

////
// Constants
////

#define	TCP_FLAGS_FIN		0x01
#define	TCP_FLAGS_SYN		0x02
#define	TCP_FLAGS_RST		0x04
#define	TCP_FLAGS_PSH		0x08
#define	TCP_FLAGS_ACK		0x10
#define	TCP_FLAGS_URG		0x20

#define TCP_STATE_CLOSE		0x00
#define TCP_STATE_LISTEN	0x01
#define TCP_STATE_SYNRCVD	0x02
#define TCP_STATE_SYNSENT	0x03
#define TCP_STATE_ESTABLISHED	0x04
#define TCP_STATE_CLOSEWAIT	0x05
#define TCP_STATE_LASTACK	0x06
#define TCP_STATE_FINWAIT1	0x07
#define TCP_STATE_FINWAIT2	0x08
#define TCP_STATE_CLOSING	0x09
#define TCP_STATE_TIMEWAIT	0x0A

#define	TCP_WINDOW_DEFAULT	1000

#define	TCP_PURE_ACK_DELAY	25000
#define	TCP_PACKET_RETRANSMIT	25000
#define TCP_PACKET_MAXTRANSMIT	10

////
// Structures
////

#pragma pack(1)

typedef struct{
  unsigned char bytes[4];
  } word32;

typedef struct{
  unsigned short int source;
  unsigned short int target;
  uint32_t sequence;
  uint32_t ack;
  unsigned short int mixed;
  unsigned short int window;
  unsigned short int checksum;
  unsigned short int urgent;
  unsigned char options[1];
  } TCP_fields;

#define TCP_get_offset(tcp)    ((ntohs((tcp)->mixed)&0xf000)>>12)
#define TCP_get_flags(tcp)     (ntohs((tcp)->mixed)&0x003f)

#define TCP_set_offset(tcp,o)  (tcp)->mixed=htons( \
                                 ((o)<<12)|(ntohs((tcp)->mixed)&0x0fff))
#define TCP_set_flags(tcp,f)   (tcp)->mixed=htons( \
                                 (((f)&0x003f)|(ntohs((tcp)->mixed)&0xffc0)))

typedef struct{
  unsigned char code;
  unsigned char length;
  unsigned char data[1];
  } TCP_option_fields;

#pragma pack()

typedef struct{
  unsigned char state;
  SocketAddress addr_local;
  SocketAddress addr_pair;
  uint32_t seq_local,seq_local_ack;
  uint32_t seq_pair,seq_pair_ack;
  StackProcess *process;
  } TCP_connection;

typedef struct{
  int allocated;
  int size;
  TCP_connection *connections;
  } TCP_connections;

////
// Prototypes
////

#ifdef VERBOSE
void displayTCPPacket(FILE *output,TCP_fields *udp,int size);
#endif
unsigned char tcpDecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char tcpSendPacket(EventsEvent *event,EventsSelector *selector);
