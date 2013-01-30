/*
 * Definitions for UDP protocol implementation
 */

////
// Constants
////

////
// Structures
////

#pragma pack(1)

typedef struct{
  unsigned short int source;
  unsigned short int target;
  unsigned short int length;
  unsigned short int checksum; 
  unsigned char data[1];
  } UDPv6_fields;

#pragma pack()

////
// Prototypes
////

#ifdef VERBOSE
void displayUDPv6Packet(FILE *output,UDPv6_fields *udp,int size);
#endif
unsigned char udpv6DecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char udpv6SendPacket(EventsEvent *event,EventsSelector *selector);
