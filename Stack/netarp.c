/*
 * Code for ARP/RARP protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "netarp.h"
#include "stack.h"

////
// Local constants
////

#define ARP_CACHE_BLOCK_SIZE	16
#define MAX_STRING		1024

////
// Global variables
////

static ARP_cache *cache=NULL;
static int triggerEvent=-1;

////
// Prototypes
////

static void arpPurgeCache(void);
static ARP_cache_entry *arpSearchInCache(EthernetAddress ethernet,IPv4Address ip);
static void arpAddToCache(IPv4Address ip,EthernetAddress ethernet,unsigned char force);
static unsigned char triggerAction(EventsEvent *event,EventsSelector *selector);

////
// Functions
////

#ifdef VERBOSE
//
// Display ARP packet
//

void displayARPPacket(FILE *output,ARP_fields *arp,int size){
unsigned char *addresses=arp->addresses;
EthernetAddress eth_sender=ethernetArray2Address(addresses);
addresses += ETHERNET_ADDRESS_SIZE;
IPv4Address ipv4_sender=ipArray2Address(addresses);
addresses += IPV4_ADDRESS_SIZE;
EthernetAddress eth_target=ethernetArray2Address(addresses);
addresses += ETHERNET_ADDRESS_SIZE;
IPv4Address ipv4_target=ipArray2Address(addresses);
int opcode=ntohs(arp->opcode);
char *opname="unknown";
switch(opcode){
  case ARP_OPCODE_REQUEST: opname="request"; break;
  case ARP_OPCODE_ANSWER: opname="answer"; break;
  case RARP_OPCODE_REQUEST: opname="reverse request"; break;
  case RARP_OPCODE_ANSWER: opname="reverse answer"; break;
  }
fprintf(stderr,"ARP Operation: %s\n",opname);
fprintf(stderr,"ARP Sender Ethernet Address: %s\n",
                ethernetAddress2String(eth_sender));
fprintf(stderr,"ARP Sender IPv4 Address: %s\n",ipAddress2String(ipv4_sender));
fprintf(stderr,"ARP Target Ethernet Address: %s\n",
                ethernetAddress2String(eth_target));
fprintf(stderr,"ARP Target IPv4 Address: %s\n",ipAddress2String(ipv4_target));
}
#endif

//
// Decode ARP packet
//

unsigned char arpDecodePacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"data",0)<0) { arraysFreeArray(infos); return 1; }
AARRAY_MGETREF(infos,data,unsigned char *);
arraysFreeArray(infos);
StackLayers *parp=stackFindLayerByProtocol(LEVEL_ARESOL_IPV4,ETHERNET_PROTO_ARP);
if(parp==NULL || parp->event_out<0){ free(data); return 0; }
ARP_fields *fields=(ARP_fields *)data;
if(ntohs(fields->hw_type)!=ARP_HW_TYPE_ETHERNET || 
   ntohs(fields->proto_type)!=ARP_PROTO_TYPE_IPV4)
  { free(data); return 0; }
#ifdef VERBOSE
fprintf(stderr,"Incoming (R)ARP packet:\n");
displayARPPacket(stderr,fields,data_size);
#endif
EthernetAddress eth_sender,eth_target;
IPv4Address ipv4_sender,ipv4_target;
int offset=sizeof(ARP_fields)-1;
eth_sender=ethernetArray2Address(data+offset);
offset += ETHERNET_ADDRESS_SIZE;
ipv4_sender=ipArray2Address(data+offset);
offset += IPV4_ADDRESS_SIZE;
eth_target=ethernetArray2Address(data+offset);
offset += ETHERNET_ADDRESS_SIZE;
ipv4_target=ipArray2Address(data+offset);
int opcode=htons(fields->opcode);
free(data);
if(opcode==ARP_OPCODE_REQUEST){
  EthernetInterface *device=stackFindEthernetDeviceByIPv4(ipv4_target);
  if(device!=NULL){
    EthernetAddress msrc=device->ether_addr;
    unsigned short int protocol=ETHERNET_PROTO_ARP;
    AssocArray *arp_infos=NULL;
    AARRAY_FSETVAR(arp_infos,mdst,eth_sender);
    AARRAY_MSETVAR(arp_infos,msrc);
    AARRAY_FSETVAR(arp_infos,ldst,ipv4_sender);
    AARRAY_FSETVAR(arp_infos,lsrc,ipv4_target);
    AARRAY_FSETVAR(arp_infos,proto,protocol);
    if(eventsTrigger(parp->event_out,arp_infos)<0){
      fprintf(stderr,"Cannot trigger arp out event !\n");
      exit(-1);
      }
    }
  }
if(opcode==RARP_OPCODE_REQUEST){
  EthernetInterface *device=stackFindEthernetDeviceByAddr(eth_target);
  if(device!=NULL){
    IPv4Address lsrc=device->IPv4[0].address;
    EthernetAddress msrc=device->ether_addr;
    unsigned short int protocol=ETHERNET_PROTO_RARP;
    AssocArray *arp_infos=NULL;
    AARRAY_FSETVAR(arp_infos,mdst,eth_sender);
    AARRAY_MSETVAR(arp_infos,msrc);
    AARRAY_FSETVAR(arp_infos,ldst,ipv4_sender);
    AARRAY_MSETVAR(arp_infos,lsrc);
    AARRAY_FSETVAR(arp_infos,proto,protocol);
    if(eventsTrigger(parp->event_out,arp_infos)<0){
      fprintf(stderr,"Cannot trigger arp out event !\n");
      exit(-1);
      }
    }
  }
if(opcode==ARP_OPCODE_ANSWER)
  arpAddToCache(ipv4_sender,eth_sender,0);
return 0;
}

//
// Send ARP packet
//

unsigned char arpSendPacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"mdst",0)<0 || arraysTestIndex(infos,"msrc",0)<0 ||
   arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"lsrc",0)<0 ||
   arraysTestIndex(infos,"proto",0)<0)
  { arraysFreeArray(infos); return 1; }
StackLayers *pether=stackFindLayerByProtocol(LEVEL_LINK,0x0000);
if(pether==NULL || pether->event_out<0){ arraysFreeArray(infos); return 0; }
AARRAY_MGETVAR(infos,mdst,EthernetAddress);
AARRAY_MGETVAR(infos,msrc,EthernetAddress);
AARRAY_MGETVAR(infos,ldst,IPv4Address);
AARRAY_MGETVAR(infos,lsrc,IPv4Address);
AARRAY_FGETVAR(infos,proto,unsigned short int,protocol);
arraysFreeArray(infos);
int size=sizeof(ARP_fields)-1+2*ETHERNET_ADDRESS_SIZE+2*IPV4_ADDRESS_SIZE;
unsigned char *packet=(unsigned char *)malloc(size);
if(packet==NULL){ perror("arpSendPacket.malloc"); return 0; }
ARP_fields *fields=(ARP_fields *)packet;
fields->hw_type=htons(ARP_HW_TYPE_ETHERNET);
fields->proto_type=htons(ARP_PROTO_TYPE_IPV4);
fields->hw_addr_len=ETHERNET_ADDRESS_SIZE;
fields->proto_addr_len=IPV4_ADDRESS_SIZE;
unsigned char arp_request=ethernetCompare(mdst,ETHERNET_ADDRESS_NULL);
unsigned char rarp_request=ipCompare(ldst,IPV4_ADDRESS_NULL);
int opcode;
if(protocol==ETHERNET_PROTO_ARP)
  opcode=arp_request?ARP_OPCODE_REQUEST:ARP_OPCODE_ANSWER;
if(protocol==ETHERNET_PROTO_RARP)
  opcode=rarp_request?RARP_OPCODE_REQUEST:RARP_OPCODE_ANSWER;
fields->opcode=htons(opcode);
int offset=sizeof(ARP_fields)-1;
ethernetAddress2Array(msrc,packet+offset);
offset += ETHERNET_ADDRESS_SIZE;
ipAddress2Array(lsrc,packet+offset);
offset += IPV4_ADDRESS_SIZE;
ethernetAddress2Array(mdst,packet+offset);
offset += ETHERNET_ADDRESS_SIZE;
ipAddress2Array(ldst,packet+offset);
offset += IPV4_ADDRESS_SIZE;
#ifdef VERBOSE
fprintf(stderr,"Outgoing ARP packet:\n");
displayARPPacket(stderr,fields,offset);
#endif
EthernetAddress edst=mdst;
if(ethernetCompare(mdst,ETHERNET_ADDRESS_NULL)){
  edst=ETHERNET_ADDRESS_BROADCAST;
  arpAddToCache(ldst,ETHERNET_ADDRESS_NULL,1);
  }
AssocArray *ether_infos=NULL;
AARRAY_FSETREF(ether_infos,data,packet,size);
AARRAY_FSETVAR(ether_infos,dst,edst);
AARRAY_FSETVAR(ether_infos,src,msrc);
AARRAY_FSETVAR(ether_infos,proto,protocol);
if(eventsTrigger(pether->event_out,ether_infos)<0){
  fprintf(stderr,"Cannot trigger ethernet out event !\n");
  exit(-1);
  }
return 0;
}

//
// Display ARP informations in stack
//

#ifdef VERBOSE
void arpDisplay(FILE *output){
int i;
time_t now=time(NULL);
fprintf(output,"=== ARP table ===\n");
for(i=0;i<cache->size;i++){
  ARP_cache_entry *entry=cache->entries+i;
  char *ip=ipAddress2String(entry->ipv4);
  int delta=now-entry->timestamp;
  char *ether=ethernetAddress2String(entry->ethernet);
  fprintf(output,"%s at %s (age=%ds)\n",ip,ether,delta);
  }
fprintf(output,"=================\n");
}
#endif

//
// Purge ARP cache
//

static void arpPurgeCache(){
int i,j;
time_t now=time(NULL);
if(cache==NULL) return;
for(i=0;i<cache->size;i++){
  ARP_cache_entry *entry=cache->entries+i;
  unsigned char remove=0;
  int delta=now-entry->timestamp;
  if(delta>ARP_CACHE_TIMEOUT) remove=1;
  if(remove==1){
    for(j=i+1;j<cache->size;j++) cache->entries[j-1]=cache->entries[j];
    cache->size--; i--;
    }
  }
}

//
// Internal function to find entry in ARP cache
//

static ARP_cache_entry *arpSearchInCache(EthernetAddress ethernet,IPv4Address ip){
int i;
arpPurgeCache();
if(cache!=NULL)
  for(i=0;i<cache->size;i++){
    ARP_cache_entry *entry=cache->entries+i;
    if((!ethernetCompare(ethernet,ETHERNET_ADDRESS_NULL) &&
        ethernetCompare(ethernet,entry->ethernet)) ||
       (!ipCompare(ip,IPV4_ADDRESS_NULL) &&
        ipCompare(ip,entry->ipv4)))
      return entry;
    }
return NULL;
}

//
// Add entry to ARP cache
//

static void arpAddToCache(
  IPv4Address ip,EthernetAddress ethernet,unsigned char force){
time_t now=time(NULL);
arpPurgeCache();
if(cache==NULL){
  cache=(ARP_cache *)malloc(sizeof(ARP_cache));
  if(cache==NULL){ perror("arpAddToCache.malloc"); return; }
  cache->allocated=0;
  cache->size=0;
  cache->entries=NULL;
  }
ARP_cache_entry *entry=arpSearchInCache(ETHERNET_ADDRESS_NULL,ip);
if(entry!=NULL){
  if(!ethernetCompare(ethernet,ETHERNET_ADDRESS_NULL))
    eventsWake(&(entry->ipv4),sizeof(IPv4Address));
  entry->ethernet=ethernet;
  entry->timestamp=now;
  goto arpAddToCacheExit;
  }
if(!force) goto arpAddToCacheExit;
int i=cache->size;
if(i>=cache->allocated){
  int newsize=(cache->allocated+ARP_CACHE_BLOCK_SIZE)*sizeof(ARP_cache_entry);
  ARP_cache_entry *newent=(ARP_cache_entry *)_realloc(cache->entries,newsize);
  if(newent==NULL){ perror("arpAddToCache.realloc"); return; }
  cache->allocated += ARP_CACHE_BLOCK_SIZE;
  cache->entries=newent;
  }
cache->size++;
cache->entries[i].ipv4=ip;
cache->entries[i].ethernet=ethernet;
cache->entries[i].timestamp=now;
if(ethernetCompare(ethernet,ETHERNET_ADDRESS_NULL)){
  // Creation of an incomplete entry
  if(triggerEvent<0){
    triggerEvent=eventsCreate(0,NULL);
    eventsAddAction(triggerEvent,triggerAction,0);
    }
  char *data=(char *)malloc(sizeof(IPv4Address));
  if(data==NULL){ perror("arpAddToCache.malloc"); return; }
  memcpy(data,&ip,sizeof(IPv4Address));
  eventsSchedule(triggerEvent,ARP_ANSWER_TIMEOUT,data);
  }

arpAddToCacheExit:

#ifdef VERBOSE
arpDisplay(stderr);
#endif
return;
}

//
// Interfaces for searches in ARP cache
//

unsigned char arpCacheFindMaterial(void *material,void *logical){
EthernetAddress *ethernet=(EthernetAddress *)material;
IPv4Address *ip=(IPv4Address *)logical;
ARP_cache_entry *entry=arpSearchInCache(ETHERNET_ADDRESS_NULL,*ip);
if(entry!=NULL && !ethernetCompare(entry->ethernet,ETHERNET_ADDRESS_NULL))
  { *ethernet=entry->ethernet; return 1; }
return 0;
}

unsigned char arpCacheFindLogical(void *material,void *logical){
EthernetAddress *ethernet=(EthernetAddress *)material;
IPv4Address *ip=(IPv4Address *)logical;
ARP_cache_entry *entry=arpSearchInCache(*ethernet,IPV4_ADDRESS_NULL);
if(entry!=NULL){ *ip=entry->ipv4; return 1; }
return 0;
}

//
// Action used by ARP trigger event
//

static unsigned char triggerAction(EventsEvent *event,EventsSelector *selector){
eventsWake(selector->data_this,sizeof(IPv4Address));
free(selector->data_this);
return 0;
}
