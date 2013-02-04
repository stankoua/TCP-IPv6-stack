/*
 * Code for virtual processes
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "stack.h"

////
// Constants
////

////
// Global variables
////

////
// Processus implementing an UDP echo
////

#define UDP_ECHO_PROMPT		"> "
unsigned char udp_echo( unsigned char type, SocketAddress to,SocketAddress from,
                        unsigned char *data,int size)
{
    printf("udp_echo: type=%x\n",type);
    if(type==PROCESS_DATA){
        printf("udp_echo: (%s,%hu)",ipAddress2String(from.address),from.port);
        printf("->(%s,%hu)\n",ipAddress2String(to.address),to.port);
        data=(unsigned char *)realloc(data,size+2);
        memmove(data+2,data,size);
        memcpy(data,UDP_ECHO_PROMPT,strlen(UDP_ECHO_PROMPT));
        return stackUDPSendDatagram(from.address,from.port,data,size+2);
    }
    return 0;
}

unsigned char udp6_echo( unsigned char type,SocketAddress to,SocketAddress from,
                         unsigned char *data,int size)
{
    printf("udp6_echo: type=%x\n",type);
    if(type==PROCESS_DATA){
        printf("udp6_echo: (%s,%hu)",ipv6Address2String(from.addressV6),from.port);
        printf("->(%s,%hu)\n",ipv6Address2String(to.addressV6),to.port);
        data=(unsigned char *)realloc(data,size+2);
        memmove(data+2,data,size);
        memcpy(data,UDP_ECHO_PROMPT,strlen(UDP_ECHO_PROMPT));
        return stackUDPv6SendDatagram(from.addressV6,from.port,data,size+2);
    }
    return 0;
}

////
// Processus implementing a TCP echo
////

unsigned char tcp_echo(
  unsigned char type,
  SocketAddress to,SocketAddress from,
  unsigned char *data,int size){
printf("tcp_echo: type=%x\n",type);
if(type==PROCESS_DATA){
  printf("tcp_echo: (%s,%hu)",ipAddress2String(from.address),from.port);
  printf("->(%s,%hu)\n",ipAddress2String(to.address),to.port);
  return stackTCPSendData(from.address,from.port,PROCESS_DATA,data,size);
  }
if(type==PROCESS_CLOSE)
  return stackTCPSendData(from.address,from.port,PROCESS_CLOSE,NULL,0);
return 0;
}

////
// Processus implementing an UDP client
////

#define UDP_CLIENT_MESSAGE		"hello"
unsigned char udp_client(
  unsigned char type,
  SocketAddress to,SocketAddress from,
  unsigned char *data,int size){
printf("udp_client: type=%x\n",type);
switch(type){
  case PROCESS_INIT:{
    IPv4Address target_ip={{192,168,100,1}};
    unsigned short int target_port=4000;
    int size_out=strlen(UDP_CLIENT_MESSAGE);
    unsigned char *data_out=(unsigned char *)malloc(size_out);
    if(data_out!=NULL){
      strncpy((char *)data_out,UDP_CLIENT_MESSAGE,size_out);
      return stackUDPSendDatagram(target_ip,target_port,data_out,size_out);
      }
    break;
    }
  case PROCESS_DATA:{
    int i;
    printf("udp_client: (%s,%hu)",ipAddress2String(from.address),from.port);
    printf("->(%s,%hu)\n",ipAddress2String(to.address),to.port);
    printf("udp_client: data=");
    for(i=0;i<size;i++) printf("%c",data[i]);
    printf("\n");
    free(data);
    break;
    }
  }
return 0;
}
