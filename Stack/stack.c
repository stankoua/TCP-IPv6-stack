/*
 * Code for virtual machine
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>

#include <libarrays.h>
#include <libevents.h>
#include <libtap.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "netarp.h"
#include "neticmp.h"
#include "neticmpv6.h"
#include "neticmpv6nd.h"
#include "netudp.h"
#include "netudpv6.h"
#include "stack.h"
#include "nettcp.h"

#include "processes.h"

////
// Constants
////

#define EVENTS_PRIORITY_DEVICE	0
#define EVENTS_PRIORITY_LAYER	10
#define EVENTS_PRIORITY_PROCESS	20

#define STACK_ETHERNET_MULTICAST_BLOCK	8
#define STACK_IPV6_MULTICAST_BLOCK	8

////
// Global variables
////

static SocketAddress localAddr;

static NetworkAddressesIPv4 eth0_ipv4[]={
    { {{192,168,100,100}}, 24 },
    { {{0,0,0,0}}, 0 }
  };

static NetworkAddressesIPv6 eth0_ipv6[]={
    { {{0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04}}, 64 },
    { {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}, 0 }
  };

static EthernetInterface ethernet_interfaces[]={
  {-1,INTERFACE_TYPE_ETHERNET,-1,"eth0","",
    {{0x00,0x01,0x02,0x03,0x04,0x05}},NULL,
    eth0_ipv4,eth0_ipv6,NULL}
  };

static GenericInterface *interfaces[]={
  (GenericInterface *)(ethernet_interfaces+0),
  NULL
  };

static AddressResolutionModule resolvModules[]={
  {MATADDR_ETHERNET,LOGADDR_IPV4,arpCacheFindMaterial},
  {MATADDR_ETHERNET,LOGADDR_IPV6,icmpv6NDFindMaterial},
  {-1,-1,NULL}
  };

static StackLayers stackLayers[]={
  {-1,LEVEL_LINK,0x0000,ethernetInitialize,ethernetDecodePacket,ethernetSendPacket,-1,-1},
  {-1,LEVEL_NETWORK,ETHERNET_PROTO_IP,NULL,ipDecodePacket,ipSendPacket,-1,-1},
  {-1,LEVEL_NETWORK,ETHERNET_PROTO_IPV6,ipv6Initialize,ipv6DecodePacket,ipv6SendPacket,-1,-1},
  {-1,LEVEL_ARESOL_IPV4,ETHERNET_PROTO_ARP,NULL,arpDecodePacket,arpSendPacket,-1,-1},
  {-1,LEVEL_ARESOL_IPV4,ETHERNET_PROTO_RARP,NULL,arpDecodePacket,arpSendPacket,-1,-1},
  {-1,LEVEL_CONTROL_IPV4,IPV4_PROTOCOL_ICMP,NULL,icmpDecodePacket,icmpSendPacket,-1,-1},
  {-1,LEVEL_TRANSPORT,IPV4_PROTOCOL_UDP,NULL,udpDecodePacket,udpSendPacket,-1,-1},
  {-1,LEVEL_TRANSPORT,IPV4_PROTOCOL_TCP,NULL,tcpDecodePacket,tcpSendPacket,-1,-1},
  {-1,LEVEL_CONTROL_IPV6,IPV6_PROTOCOL_ICMP,NULL,icmpv6DecodePacket,icmpv6SendPacket,-1,-1},
  {-1,LEVEL_CONTROL_IPV6,ICMPV6_LEVEL_NEIGHBOR_DISCOVERY,
      icmpv6ndInitialize,icmpv6ndDecodePacket,icmpv6ndSendPacket,-1,-1},
  {-1,LEVEL_TRANSPORT_IPV6,IPV6_PROTOCOL_UDP,NULL,udpv6DecodePacket,udpv6SendPacket,-1,-1},
  {-1,-1,-1,NULL,NULL,NULL,-1,-1}
  };

static StackProcess stackProcess[]={
  {IPV4_PROTOCOL_UDP,{{0,0,0,0}},{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},4000,udp_echo,-1},
  {IPV4_PROTOCOL_UDP,{{0,0,0,0}},{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},30000,udp_client,-1},
  {IPV4_PROTOCOL_TCP,{{0,0,0,0}},{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},5000,tcp_echo,-1},
  {0,{{0,0,0,0}},{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},0,NULL,-1}
  };

////
// Prototypes
////

static void stackInitializeDevices(void);
static void stackInitializeLayers(void);
static unsigned char stackHandleTransportData(
  EventsEvent *event,EventsSelector *selector);
static void stackInitializeProcesses(void);

////
// Functions on network interface structure
////

//
// Add Ethernet multicast address
//
unsigned char stackAddEthernetMulticast(
  EthernetMulticastAddresses *multicast,EthernetAddress new){
if(multicast->size<=multicast->allocated){
  multicast->allocated += STACK_ETHERNET_MULTICAST_BLOCK;
  multicast->addresses=(EthernetAddress *)
   _realloc(multicast->addresses,multicast->allocated*sizeof(EthernetAddress));
  if(multicast->addresses==NULL)
    { perror("stackAddEthernetMulticast.realloc"); return 0; }
  }
multicast->addresses[multicast->size++]=new;
return 1;
}

//
// Remove Ethernet multicast address
//
unsigned char stackDelEthernetMulticast(
  EthernetMulticastAddresses *multicast,EthernetAddress del){
int i,j;
unsigned char found=0;
if(multicast==NULL) return found;
for(i=0;i<multicast->size;)
  if(ethernetCompare(multicast->addresses[i],del)){
    found=1;
    for(j=i+1;j<multicast->size;j++)
      multicast->addresses[j-1]=multicast->addresses[j];
    multicast->size--;
    }
  else i++;
return found;
}

//
// Find Ethernet multicast address
//
unsigned char stackFindEthernetMulticast(
  EthernetMulticastAddresses *multicast,EthernetAddress address){
int i;
if(multicast==NULL) return 0;
for(i=0;i<multicast->size;i++)
  if(ethernetCompare(multicast->addresses[i],address)) return 1;
return 0;
}

//
// Add IPv6 multicast address
//
unsigned char stackAddIPv6Multicast(
  IPv6MulticastAddresses *multicast,IPv6Address new){
if(multicast->size<=multicast->allocated){
  multicast->allocated += STACK_IPV6_MULTICAST_BLOCK;
  multicast->addresses=(IPv6Address *)
   _realloc(multicast->addresses,multicast->allocated*sizeof(IPv6Address));
  if(multicast->addresses==NULL)
    { perror("stackAddIPv6Multicast.realloc"); return 0; }
  }
multicast->addresses[multicast->size++]=new;
return 1;
}

//
// Remove IPv6 multicast address
//
unsigned char stackDelIPv6Multicast(
  IPv6MulticastAddresses *multicast,IPv6Address del){
int i,j;
unsigned char found=0;
if(multicast==NULL) return found;
for(i=0;i<multicast->size;)
  if(ipv6Compare(multicast->addresses[i],del)){
    found=1;
    for(j=i+1;j<multicast->size;j++)
      multicast->addresses[j-1]=multicast->addresses[j];
    multicast->size--;
    }
  else i++;
return found;
}

//
// Find IPv6 multicast address
//
unsigned char stackFindIPv6Multicast(
  IPv6MulticastAddresses *multicast,IPv6Address address){
int i;
if(multicast==NULL) return 0;
for(i=0;i<multicast->size;i++)
  if(ipv6Compare(multicast->addresses[i],address)) return 1;
return 0;
}

//
// Find a network interface structure by identity
//
GenericInterface *stackFindDeviceByIdentity(int identity){
int i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->identity==identity) return interfaces[i];
  i++;
  }
return NULL;
}

//
// Find a network interface structure by address
//
EthernetInterface *stackFindEthernetDeviceByAddr(EthernetAddress src){
int i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->type!=INTERFACE_TYPE_ETHERNET) continue;
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  if(ethernetCompare(ethernet_interface->ether_addr,src))
    return ethernet_interface;
  i++;
  }
return NULL;
}

//
// Find a network interface structure by name
//
EthernetInterface *stackFindEthernetDeviceByName(char *name){
int i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->type!=INTERFACE_TYPE_ETHERNET) continue;
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  if(strcmp(ethernet_interface->name_int,name)==0)
    return ethernet_interface;
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv4 address
//
EthernetInterface *stackFindEthernetDeviceByIPv4(IPv4Address ip){
int i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->type!=INTERFACE_TYPE_ETHERNET) continue;
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  int j=0;
  while(!ipCompare(ethernet_interface->IPv4[j].address,IPV4_ADDRESS_NULL)){
    if(ipCompare(ethernet_interface->IPv4[j].address,ip))
      return ethernet_interface;
    j++;
    }
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv4 broadcast
//
EthernetInterface *stackFindEthernetDeviceByIPv4Broadcast(IPv4Address ip){
int i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->type!=INTERFACE_TYPE_ETHERNET) continue;
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  int j=0;
  while(!ipCompare(ethernet_interface->IPv4[j].address,IPV4_ADDRESS_NULL)){
    IPv4Address bdc=ipBroadcast(ethernet_interface->IPv4[j].address,
                                ethernet_interface->IPv4[j].netmask);
    if(ipCompare(bdc,ip)) return ethernet_interface;
    j++;
    }
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv4 network
//
EthernetInterface *stackFindEthernetDeviceByIPv4Network(IPv4Address ip){
int i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->type!=INTERFACE_TYPE_ETHERNET) continue;
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  int j=0;
  while(!ipCompare(ethernet_interface->IPv4[j].address,IPV4_ADDRESS_NULL)){
    IPv4Address inet=ipNetwork(ip,ethernet_interface->IPv4[j].netmask);
    IPv4Address tnet=ipNetwork(ethernet_interface->IPv4[j].address,
                               ethernet_interface->IPv4[j].netmask);
    if(ipCompare(inet,tnet)) return ethernet_interface;
    j++;
    }
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv6 address
//
EthernetInterface *stackFindEthernetDeviceByIPv6(IPv6Address ip){
int i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->type!=INTERFACE_TYPE_ETHERNET) continue;
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  int j=0;
  while(!ipv6Compare(ethernet_interface->IPv6[j].address,IPV6_ADDRESS_NULL)){
    if(ipv6Compare(ethernet_interface->IPv6[j].address,ip))
      return ethernet_interface;
    j++;
    }
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv6 multicast
//
EthernetInterface *stackFindEthernetDeviceByIPv6Multicast(IPv6Address mcast){
int i,j;
i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->type!=INTERFACE_TYPE_ETHERNET) continue;
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  IPv6MulticastAddresses *multicast=ethernet_interface->IPv6_multicast;
  if(multicast!=NULL)
    for(j=0;j<multicast->size;j++)
      if(ipv6Compare(multicast->addresses[j],mcast))
        return ethernet_interface;
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv6 network
//
EthernetInterface *stackFindEthernetDeviceByIPv6Network(IPv6Address ip){
int i=0;
while(interfaces[i]!=NULL){
  if(interfaces[i]->type!=INTERFACE_TYPE_ETHERNET) continue;
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  int j=0;
  while(!ipv6Compare(ethernet_interface->IPv6[j].address,IPV6_ADDRESS_NULL)){
    IPv6Address inet=ipv6Network(ip,ethernet_interface->IPv6[j].netmask);
    IPv6Address tnet=ipv6Network(ethernet_interface->IPv6[j].address,
                                 ethernet_interface->IPv6[j].netmask);
    if(ipv6Compare(inet,tnet)) return ethernet_interface;
    j++;
    }
  i++;
  }
return NULL;
}

////
// Functions on layer structure
////

//
// Find a layer by protocol
//
StackLayers *stackFindLayerByProtocol(int level,int protocol){
int i=0;
while(stackLayers[i].level>=0){
  if(stackLayers[i].level==level &&
     stackLayers[i].protocol==protocol)
    return stackLayers+i;
  i++;
  }
return NULL;
}

//
// Find a layer by identity
//
StackLayers *stackFindLayerByIdentity(int identity){
int i=0;
while(stackLayers[i].level>=0){
  if(stackLayers[i].identity==identity) return stackLayers+i;
  i++;
  }
return NULL;
}

//
// Initialize stack layers
//
static void stackInitializeLayers(void){
static int identity=0;
int i=0;
while(stackLayers[i].level>=0){
  if(stackLayers[i].identity<0) stackLayers[i].identity=identity++;
  if(stackLayers[i].action_in!=NULL){
    int e=eventsCreate(EVENTS_PRIORITY_LAYER,&(stackLayers[i]));
    if(e<0){
      fprintf(stderr,"Cannot create in event for layer level %d id %d",
                     stackLayers[i].level,stackLayers[i].identity);
      exit(-1);
      }
    if(eventsAddAction(e,stackLayers[i].action_in,0)<0){
      fprintf(stderr,"Cannot add action to in event for layer level %d id %d",
                     stackLayers[i].level,stackLayers[i].identity);
      exit(-1);
      }
    stackLayers[i].event_in=e;
    }
  if(stackLayers[i].action_out!=NULL){
    int e=eventsCreate(EVENTS_PRIORITY_LAYER,&(stackLayers[i]));
    if(e<0){
      fprintf(stderr,"Cannot create out event for layer level %d id %d",
                     stackLayers[i].level,stackLayers[i].identity);
      exit(-1);
      }
    if(eventsAddAction(e,stackLayers[i].action_out,0)<0){
      fprintf(stderr,"Cannot add action to in event for layer level %d id %d",
                     stackLayers[i].level,stackLayers[i].identity);
      exit(-1);
      }
    stackLayers[i].event_out=e;
    }
  i++;
  }
}

//
// Open network interfaces
//
static void stackInitializeDevices(void){
static int identity=0;
int i=0;
int ether_in=-1;
while(interfaces[i]!=NULL){
  GenericInterface *interface=interfaces[i];
  if(interface->identity<0) interface->identity=identity++;
  switch(interface->type){
    case INTERFACE_TYPE_ETHERNET:
      // Find Ethernet incoming event
      if(ether_in<0){
        StackLayers *ethernet=stackFindLayerByProtocol(LEVEL_LINK,0x0000);
        if(ethernet==NULL){
          fprintf(stderr,"Cannot found Ethernet layer!");
          exit(-1);
          }
        ether_in=ethernet->event_in;
        }
      // Create TAP descriptor and associate it to the adequate event
      EthernetInterface *intf=(EthernetInterface *)interface;
      strcpy(intf->name_tap,"");
      int tap=allocateNetworkDevice(intf->name_tap,IFF_TAP|IFF_NO_PI);
      if(tap<0){
        fprintf(stderr,"Cannot open %s TAP interface!\n",intf->name_int);
        exit(-1);
        }
      if(eventsAssociateDescriptor(ether_in,tap,intf)<0){
        fprintf(stderr,"Cannot add selector to event for Ethernet interface %s !\n",
                       intf->name_int);
        exit(-1);
        }
      intf->descriptor=tap;
      break;
    }
  // Initialize layers for this interface
  int l=0;
  while(stackLayers[l].level>=0){
    if(stackLayers[l].initialize!=NULL){
      AssocArray *infos=NULL;
      AARRAY_FSETVAR(infos,intf,interface);
      stackLayers[l].initialize(infos);
      }
    l++;
    }
  i++;
  }
}

//
// Display network interfaces structure
//
void stackDisplayDevices(FILE *output){
int i,j;
for(i=0;interfaces[i]!=NULL;i++){
  EthernetInterface *ethernet_interface=(EthernetInterface *)interfaces[i];
  fprintf(output,"Interface %s :\n",ethernet_interface->name_int);
  fprintf(output,"  TAP=%s",ethernet_interface->name_tap); 
  fprintf(output,"  MAC=%s\n",ethernetAddress2String(ethernet_interface->ether_addr)); 
  fprintf(output,"  Ethernet multicast="); 
  EthernetMulticastAddresses *mether=ethernet_interface->ether_multicast;
  if(mether!=NULL)
    for(j=0;j<mether->size;j++){
      if(j>0) fprintf(output,",");
      fprintf(output,"%s",ethernetAddress2String(mether->addresses[j]));
      }
  fprintf(output,"\n"); 
  fprintf(output,"  IPv4="); 
  j=0;
  while(!ipCompare(ethernet_interface->IPv4[j].address,IPV4_ADDRESS_NULL)){
    if(j>0) fprintf(output,",");
    fprintf(output,"%s",ipAddress2String(ethernet_interface->IPv4[j].address));
    fprintf(output,"/%d",ethernet_interface->IPv4[j].netmask);
    j++;
    }
  fprintf(output,"\n"); 
  fprintf(output,"  IPv6="); 
  j=0;
  while(!ipv6Compare(ethernet_interface->IPv6[j].address,IPV6_ADDRESS_NULL)){
    if(j>0) fprintf(output,",");
    fprintf(output,"%s",ipv6Address2String(ethernet_interface->IPv6[j].address));
    fprintf(output,"/%d",ethernet_interface->IPv6[j].netmask);
    j++;
    }
  fprintf(output,"\n"); 
  fprintf(output,"  IPv6 multicast="); 
  IPv6MulticastAddresses *mipv6=ethernet_interface->IPv6_multicast;
  if(mipv6!=NULL)
    for(j=0;j<mipv6->size;j++){
      if(j>0) fprintf(output,",");
      fprintf(output,"%s",ipv6Address2String(mipv6->addresses[j]));
      }
  fprintf(output,"\n"); 
  }
}

////
// Functions on address resolution 
////

//
// Resolve IPv4 address into Ethernet address
//
unsigned char stackAddressResolution(int mtype,int ltype,void *maddr,void *laddr){
AddressResolutionModule *module=resolvModules;
while(module->material>=0){
  if(module->material==mtype && module->logical==ltype){
    return module->function(maddr,laddr);
    }
  module++;
  }
switch(module->material){
  case MATADDR_ETHERNET:
    *((EthernetAddress *)maddr)=ETHERNET_ADDRESS_BROADCAST;
    return 1;
  }
return 0;
}

////
// Functions about checksum
////

//
// Generic checksum computation
//

unsigned short int genericChecksum(unsigned char *bytes,int size,int init){
long int checksum=init;
int i;
for(i=0;i<size;i += 2){
  unsigned char b1=bytes[i];
  unsigned char b2=(i+1<size)?bytes[i+1]:0;
  checksum += b1<<8 | b2;
  }
while(checksum>>16) checksum=(checksum&0xffff)+(checksum>>16);
return ~(unsigned short int)checksum;
}

////
// Functions about processes
////

//
// Find a specific process 
//
StackProcess *stackFindProcess(
  unsigned char protocol,IPv4Address address,short int port){
int i=0;
while(stackProcess[i].process!=NULL){
  if(stackProcess[i].protocol==protocol &&
     (ipCompare(stackProcess[i].address,IPV4_ADDRESS_NULL) ||
      ipCompare(stackProcess[i].address,address)) &&
     stackProcess[i].port==port)
    return stackProcess+i;
  i++;
  }
return NULL;
}

StackProcess *stackFindProcessIpv6(
  unsigned char protocol,IPv6Address address,short int port){
int i=0;
while(stackProcess[i].process!=NULL){
  if(stackProcess[i].protocol==protocol &&
     (ipv6Compare(stackProcess[i].addressv6,IPV6_ADDRESS_NULL) ||
      ipv6Compare(stackProcess[i].addressv6,address)) &&
     stackProcess[i].port==port)
    return stackProcess+i;
  i++;
  }
return NULL;
}

//
// Function used by processes to send UDP datagram
//
unsigned char stackUDPSendDatagram(
  IPv4Address to_ip,unsigned short int to_port,unsigned char *data,int size){
StackLayers *pudp=stackFindLayerByProtocol(LEVEL_TRANSPORT,IPV4_PROTOCOL_UDP);
if(pudp==NULL || pudp->event_out<0) return 1;
if(localAddr.port==0){ perror("stackUDPSendDatagram"); exit(-1); }
AssocArray *udp_infos=NULL;
AARRAY_FSETVAR(udp_infos,ldst,to_ip);
AARRAY_FSETVAR(udp_infos,pdst,to_port);
AARRAY_FSETVAR(udp_infos,psrc,localAddr.port);
AARRAY_FSETREF(udp_infos,data,data,size);
if(eventsTrigger(pudp->event_out,udp_infos)<0){
  fprintf(stderr,"Cannot trigger UDP out event !\n");
  exit(-1);
  }
return 0;
}

unsigned char stackUDPv6SendDatagram(
        IPv6Address to_ip,unsigned short int to_port,unsigned char *data,int size){
    StackLayers *pudp=stackFindLayerByProtocol(LEVEL_TRANSPORT,IPV6_PROTOCOL_UDP);
    if(pudp==NULL || pudp->event_out<0) return 1;
    if(localAddr.port==0){ perror("stackUDPv6SendDatagram"); exit(-1); }
    AssocArray *udp_infos=NULL;
    AARRAY_FSETVAR(udp_infos,ldst,to_ip);
    AARRAY_FSETVAR(udp_infos,pdst,to_port);
    AARRAY_FSETVAR(udp_infos,psrc,localAddr.port);
    AARRAY_FSETREF(udp_infos,data,data,size);
    if(eventsTrigger(pudp->event_out,udp_infos)<0){
        fprintf(stderr,"Cannot trigger UDPv6 out event !\n");
        exit(-1);
    }
    return 0;
}


//
// Function used by processes to send TCP data
//
unsigned char stackTCPSendData(
  IPv4Address to_ip,unsigned short int to_port,
  unsigned char type,unsigned char *data,int size){
StackLayers *ptcp=stackFindLayerByProtocol(LEVEL_TRANSPORT,IPV4_PROTOCOL_TCP);
if(ptcp==NULL || ptcp->event_out<0) return 1;
unsigned char protoflag=0;
if(type==PROCESS_CONNECT) protoflag=TCP_FLAGS_SYN;
if(type==PROCESS_CLOSE) protoflag=TCP_FLAGS_FIN;
unsigned char flag=(data==NULL && size==0)?protoflag:0;
AssocArray *tcp_options=NULL;
int size_options=arraysGetSize(tcp_options);
AssocArray *tcp_infos=NULL;
AARRAY_FSETVAR(tcp_infos,ldst,to_ip);
AARRAY_FSETVAR(tcp_infos,pdst,to_port);
AARRAY_FSETVAR(tcp_infos,psrc,localAddr.port);
AARRAY_FSETREF(tcp_infos,data,data,size);
AARRAY_MSETVAR(tcp_infos,flag);
AARRAY_FSETREF(tcp_infos,opts,tcp_options,size_options);
if(eventsTrigger(ptcp->event_out,tcp_infos)<0){
  fprintf(stderr,"Cannot trigger TCP out event !\n");
  exit(-1);
  }
return 0;
}

//
// Function triggering process for transport protocol data processing
//
static unsigned char stackHandleTransportData(
  EventsEvent *event,EventsSelector *selector){
StackProcess *process=(StackProcess *)event->data_init;
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"pdst",0)<0 ||
   arraysTestIndex(infos,"lsrc",0)<0 || arraysTestIndex(infos,"psrc",0)<0 ||
   arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"type",0)<0)
  { arraysFreeArray(infos); return 0; }
SocketAddress from;
AARRAY_HGETVAR(infos,ldst,IPv4Address,localAddr.address);
if(ipCompare(localAddr.address,IPV4_ADDRESS_NULL))
  localAddr.address=process->address;
AARRAY_HGETVAR(infos,lsrc,IPv4Address,from.address);
AARRAY_MGETVAR(infos,pdst,short int);
localAddr.port=ntohs(pdst);
if(localAddr.port==0) localAddr.port=process->port;
AARRAY_MGETVAR(infos,psrc,short int);
from.port=ntohs(psrc);
AARRAY_MGETVAR(infos,type,unsigned char);
AARRAY_FGETREF(infos,data,unsigned char *,data,size);
arraysFreeArray(infos);
int status=process->process(type,localAddr,from,data,size);
localAddr.port=0;
if(status!=0) process->event=-1;
return status;
}

//
// Initialize processes
//
static void stackInitializeProcesses(void){
int i=0;
while(stackProcess[i].process!=NULL){
  int e=eventsCreate(EVENTS_PRIORITY_PROCESS,stackProcess+i);
  if(e<0){
    fprintf(stderr,"Cannot create event for process #%d !\n",i);
    exit(-1);
    }
  int status=0;
  int proto=stackProcess[i].protocol;
  switch(proto){
    case IPV4_PROTOCOL_UDP:
    case IPV4_PROTOCOL_TCP:
      status=eventsAddAction(e,stackHandleTransportData,0);
      break;
    default:
      fprintf(stderr,"Process #%d with unknown protocol %d !\n",i,proto);
    }
  if(status<0){
    fprintf(stderr,"Cannot add action for process #%d !\n",i);
    exit(-1);
    }
  stackProcess[i].event=e;
  unsigned char type=PROCESS_INIT;
  IPv4Address address=IPV4_ADDRESS_NULL;
  short int port=0;
  int size=0;
  AssocArray *infos=NULL;
  AARRAY_MSETVAR(infos,type);
  AARRAY_FSETVAR(infos,ldst,address);
  AARRAY_FSETVAR(infos,lsrc,address);
  AARRAY_FSETVAR(infos,pdst,port);
  AARRAY_FSETVAR(infos,psrc,port);
  AARRAY_FSETREF(infos,data,NULL,size);
  if(eventsTrigger(e,infos)<0){ 
    fprintf(stderr,"Cannot trigger process event (init) !\n");
    exit(-1);
    }
  i++;
  }
}

//
// Stub for reallocation with memory cleaning
//
void *_realloc(void *ptr, size_t size){
void *result=realloc(ptr,size);
if(result==NULL && size>0) free(ptr);
return result;
}

////
// Main procedure
////

int main(void){
stackInitializeLayers();
stackInitializeProcesses();
stackInitializeDevices();
stackDisplayDevices(stderr);
eventsScan();
exit(0);
}
