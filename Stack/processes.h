/*
 * Definitions for virtual processes
 */

////
// Constants
////

////
// Structures
////

////
// Prototypes
////

unsigned char udp_echo(
  unsigned char type,
  SocketAddress to,SocketAddress from,
  unsigned char *data,int size);
unsigned char udp6_echo( 
  unsigned char type, SocketAddress to,SocketAddress from,
  unsigned char *data,int size);
unsigned char tcp_echo(
  unsigned char type,
  SocketAddress to,SocketAddress from,
  unsigned char *data,int size);
unsigned char udp_client(
  unsigned char type,
  SocketAddress to,SocketAddress from,
  unsigned char *data,int size);
