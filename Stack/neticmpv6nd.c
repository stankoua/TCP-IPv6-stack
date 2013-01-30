/*
 * Code for ICMPv6 ND protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "stack.h"
#include "neticmpv6.h"
#include "neticmpv6nd.h"

////
// Local constants
////

#define	ND_ADD_FORCED		1
#define	ND_ADD_STATIC		2

#define ND_CACHE_BLOCK_SIZE	16

////
// Global variables
////

static ND_cache *cache=NULL;
static int NDEvent=-1;

////
// Prototypes
////

static void icmp6NDCachePurge(void);
static ND_cache_entry *icmpv6NDSearchInCache(EthernetAddress ethernet,IPv6Address ip);
static void icmpv6NDAddToCache(IPv6Address ip,EthernetAddress ethernet,unsigned char flags);
static unsigned char icmpv6NDAction(EventsEvent *event,EventsSelector *selector);

////
// Functions
////

#ifdef VERBOSE
//
// Display ICMPv6 ND packets
//

#define	MAX_BYTES_BY_ROW	16
void displayICMPv6NDPacket(FILE *output,int type,unsigned char *nd,int size){
IPv6Address *ip=NULL;
unsigned char *options=NULL;
switch(type){
  case ICMPV6_TYPE_NEIGHBOR_SOLICITATION:{
    ICMPv6NDsol_fields *sol=(ICMPv6NDsol_fields *)nd;
    fprintf(output,"ICMPv6 ND Solicitation\n");
    ip=&(sol->target);
    options=sol->options;
    size -= sizeof(ICMPv6NDsol_fields)-1;
    }
    break;
  case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:{
    ICMPv6NDadv_fields *adv=(ICMPv6NDadv_fields *)nd;
    unsigned char router=ICMPv6ND_get_router(adv);
    unsigned char solicited=ICMPv6ND_get_solicited(adv);
    unsigned char override=ICMPv6ND_get_override(adv);
    fprintf(output,"ICMPv6 ND Advertissement, Flags: %c%c%c\n",
                   router?'R':'_',solicited?'S':'_',override?'O':'_');
    ip=&(adv->target);
    options=adv->options;
    size -= sizeof(ICMPv6NDadv_fields)-1;
    }
    break;
  }
if(ip!=NULL) fprintf(output,"ICMPv6 ND Target: %s\n",ipv6Address2String(*ip));
if(options!=NULL) displayICMPv6Options(output,options,size);
}
#endif

//
// Initialize ICMPv6 ND protocol
//

unsigned char icmpv6ndInitialize(AssocArray *infos){
if(arraysTestIndex(infos,"intf",0)<0){ arraysFreeArray(infos); return 0; }
AARRAY_MGETVAR(infos,intf,GenericInterface *);
arraysFreeArray(infos);
// Check that interface type is Ethernet
if(intf->type!=INTERFACE_TYPE_ETHERNET) return 0;
EthernetInterface *ethernet_interface=(EthernetInterface *)intf;
// Add multicast IPv6 addresses to ND cache as static entries
if(ethernet_interface->IPv6_multicast!=NULL){
  int i,j;
  IPv6MulticastAddresses *multicast=ethernet_interface->IPv6_multicast;  
  for(i=0;i<multicast->size;i++){
    IPv6Address ip=multicast->addresses[i];
    if(ip.bytes[IPV6_ADDRESS_SIZE-4]!=0x00) continue;
    ND_cache_entry *entry=icmpv6NDSearchInCache(ETHERNET_ADDRESS_NULL,ip);
    if(entry==NULL){
      EthernetAddress ethernet=ETHERNET_ADDRESS_BROADCASTV6;
      for(j=0;j<4;j++)
        ethernet.bytes[ETHERNET_ADDRESS_SIZE-j-1]=ip.bytes[IPV6_ADDRESS_SIZE-j-1];
      icmpv6NDAddToCache(ip,ethernet,ND_ADD_STATIC);
      }
    }
  }
return 1;
}

//
// Decode ICMPv6 ND packet
//

unsigned char icmpv6ndDecodePacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ifid",0)<0 || arraysTestIndex(infos,"l3id",0)<0 ||
   arraysTestIndex(infos,"lsrc",0)<0 || arraysTestIndex(infos,"type",0)<0 ||
   arraysTestIndex(infos,"data",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_MGETVAR(infos,ifid,int);
AARRAY_MGETVAR(infos,l3id,int);
AARRAY_FGETREF(infos,lsrc,unsigned char *,source,size_address);
AARRAY_MGETVAR(infos,type,unsigned char);
AARRAY_FGETREF(infos,data,unsigned char *,data,size_data);
arraysFreeArray(infos);
#ifdef VERBOSE
fprintf(stderr,"Incoming ICMPv6 ND packet:\n");
displayICMPv6NDPacket(stderr,type,data,size_data);
#endif
switch(type){
  case ICMPV6_TYPE_NEIGHBOR_SOLICITATION:{
    StackLayers *picmpnd=stackFindLayerByProtocol(
                           LEVEL_CONTROL_IPV6,ICMPV6_LEVEL_NEIGHBOR_DISCOVERY);
    if(picmpnd!=NULL && picmpnd->event_out>=0){

      // Check that the solicitation is about our address
      ICMPv6NDsol_fields *sol=(ICMPv6NDsol_fields *)data;
      EthernetInterface *device=stackFindEthernetDeviceByIPv6(sol->target);
      if(device==NULL){ free(data); free(source); return 0; }
      unsigned char *target=malloc(size_address);
      if(target==NULL)
        { free(data); free(source);
          perror("icmpv6ndDecodePacket.malloc"); return 0; }
      memcpy(target,&(sol->target),size_address);

      // Extract MAC address and it to ND cache
      if(size_data>sizeof(ICMPv6NDsol_fields)-1){
        ICMPv6_option *option=(ICMPv6_option *)sol->options;
        if(option->type==ICMPV6_OPTION_TYPE_LLASOURCE){
          EthernetAddress ether=*((EthernetAddress *)option->data.lla);
          icmpv6NDAddToCache(*(IPv6Address *)source,ether,ND_ADD_FORCED);
          }
        }

      // Send ND advertisement packet
      AssocArray *icmpnd_infos=NULL;
      AARRAY_MSETVAR(icmpnd_infos,ifid);
      AARRAY_MSETVAR(icmpnd_infos,l3id);
      AARRAY_FSETREF(icmpnd_infos,addr,target,size_address);
      AARRAY_FSETREF(icmpnd_infos,ldst,source,size_address);
      if(eventsTrigger(picmpnd->event_out,icmpnd_infos)<0){
        fprintf(stderr,"Cannot trigger ICMPv6 ND in event !\n");
        exit(-1);
        }
      }
    }
    break;
  case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
    if(size_data>sizeof(ICMPv6NDadv_fields)-1){
      ICMPv6NDadv_fields *adv=(ICMPv6NDadv_fields *)data;
      IPv6Address addr=adv->target;
      ICMPv6_option *option=(ICMPv6_option *)adv->options;
      if(option->type==ICMPV6_OPTION_TYPE_LLATARGET){
        EthernetAddress ether=*((EthernetAddress *)option->data.lla);
        icmpv6NDAddToCache(addr,ether,0);
        }
      }
    free(source);
    break;
  default:
    free(source);
    break;
  }
free(data);
return 0;
}

//
// Send ICMPv6 packet
//

unsigned char icmpv6ndSendPacket(EventsEvent *event,EventsSelector *selector){

/* Get packet data */
AssocArray *infos=(AssocArray *)selector->data_this; 
if(arraysTestIndex(infos,"ifid",0)<0 || arraysTestIndex(infos,"l3id",0)<0 ||
   arraysTestIndex(infos,"addr",0)<0 || arraysTestIndex(infos,"ldst",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_MGETVAR(infos,ifid,int);
AARRAY_MGETVAR(infos,l3id,int);
AARRAY_FGETREF(infos,addr,unsigned char *,neighbor,size_address);
AARRAY_HGETREF(infos,ldst,unsigned char *,target);
arraysFreeArray(infos);

/* Get underlying protocols */
StackLayers *picmp=stackFindLayerByProtocol(LEVEL_CONTROL_IPV6,IPV6_PROTOCOL_ICMP);
if(picmp==NULL || picmp->event_out<0)
  { free(neighbor); free(target); return 0; }

/* Get physical address */
if(size_address!=sizeof(IPv6Address))
  { free(neighbor); free(target); return 0; }
IPv6Address ipv6_neighbor=*((IPv6Address *)neighbor);
free(neighbor);
EthernetInterface *device=stackFindEthernetDeviceByIPv6Network(ipv6_neighbor);
if(device==NULL){ free(target); return 0; }

/* Build ICMPv6 ND packet */
int type=ipv6Compare(*((IPv6Address *)target),IPV6_ADDRESS_NULL)?
           ICMPV6_TYPE_NEIGHBOR_SOLICITATION:
           ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT;
int code=ICMPV6_CODE_NONE;
unsigned char *data=NULL;
int size=-1;
switch(type){
  case ICMPV6_TYPE_NEIGHBOR_SOLICITATION:{
    int i,j;

    // Fill ND packet fields
    size=sizeof(ICMPv6NDsol_fields)-1+8;
    ICMPv6NDsol_fields *sol=malloc(size);
    if(sol==NULL)
      { free(target); perror("icmpv6ndSendPacket.malloc"); return 0; }
    bzero(sol,size);
    sol->target=ipv6_neighbor;
    ICMPv6_option *option=(ICMPv6_option *)sol->options;
    option->length=1;
    option->type=ICMPV6_OPTION_TYPE_LLASOURCE;
    memcpy(&(option->data),&(device->ether_addr),ETHERNET_ADDRESS_SIZE); 
    data=(unsigned char *)sol;

    // Build the target IPv6 multicast address
    *((IPv6Address *)target)=IPV6_PREFIX_ND;
    for(i=0;i<3;i++)
      target[IPV6_ADDRESS_SIZE-i-1]=ipv6_neighbor.bytes[IPV6_ADDRESS_SIZE-i-1];
    icmpv6NDAddToCache(ipv6_neighbor,ETHERNET_ADDRESS_NULL,ND_ADD_FORCED);

    // Add a static entry to ND cache if not present
    ND_cache_entry *entry=
      icmpv6NDSearchInCache(ETHERNET_ADDRESS_NULL,*((IPv6Address *)target));
    if(entry==NULL){
      EthernetAddress ethernet=ETHERNET_ADDRESS_BROADCASTV6;
      for(j=0;j<4;j++)
        ethernet.bytes[ETHERNET_ADDRESS_SIZE-j-1]=target[IPV6_ADDRESS_SIZE-j-1];
      icmpv6NDAddToCache(*((IPv6Address *)target),ethernet,ND_ADD_STATIC);
      }
    }
    break;
  case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:{
    size=sizeof(ICMPv6NDadv_fields)-1+8;
    ICMPv6NDadv_fields *adv=malloc(size);
    if(adv==NULL)
      { free(target); perror("icmpv6ndSendPacket.malloc"); return 0; }
    bzero(adv,size);
    adv->target=ipv6_neighbor;
    ICMPv6ND_set_solicited(adv,1);
    ICMPv6ND_set_override(adv,1);
    ICMPv6_option *option=(ICMPv6_option *)adv->options;
    option->length=1;
    option->type=ICMPV6_OPTION_TYPE_LLATARGET;
    memcpy(&(option->data),&(device->ether_addr),ETHERNET_ADDRESS_SIZE); 
    data=(unsigned char *)adv;
    }
    break;
  }
#ifdef VERBOSE
fprintf(stderr,"Outgoing ICMPv6 ND packet:\n");
displayICMPv6NDPacket(stderr,type,data,size);
#endif

/* Call ICMPv6 layer */
AssocArray *icmp_infos=NULL;
AARRAY_MSETVAR(icmp_infos,ifid);
AARRAY_MSETVAR(icmp_infos,l3id);
AARRAY_MSETVAR(icmp_infos,type);
AARRAY_MSETVAR(icmp_infos,code);
AARRAY_FSETREF(icmp_infos,data,data,size);
AARRAY_FSETREF(icmp_infos,ldst,target,size_address);
if(eventsTrigger(picmp->event_out,icmp_infos)<0){
  fprintf(stderr,"Cannot trigger ICMPv6 out event !\n");
  exit(-1);
  }
return 0;
}

//
// Display ND informations in cache
//

#ifdef VERBOSE
void icmpv6NDDisplayCache(FILE *output){
int i;
time_t now=time(NULL);
fprintf(output,"=== ND Cache ===\n");
if(cache!=NULL)
  for(i=0;i<cache->size;i++){
    ND_cache_entry *entry=cache->entries+i;
    char *ip=ipv6Address2String(entry->ipv6);
    char *ether=ethernetAddress2String(entry->ethernet);
    fprintf(output,"%s at %s ",ip,ether);
    switch(entry->type){
      case ND_ENTRY_STATIC:
        fprintf(output,"(static)\n");
        break;
      case ND_ENTRY_DYNAMIC:{
        int delta=now-entry->timestamp;
        fprintf(output,"(dynamic, age=%ds)\n",delta);
        }
        break;
      }
    }
fprintf(output,"=================\n");
}
#endif

//
// Purge ND cache
//

static void icmp6NDCachePurge(void){
int i,j;
time_t now=time(NULL);
if(cache==NULL) return;
for(i=0;i<cache->size;i++){
  ND_cache_entry *entry=cache->entries+i;
  if(entry->type!=ND_ENTRY_DYNAMIC) continue;
  unsigned char remove=0;
  int delta=now-entry->timestamp;
  if(delta>ND_CACHE_TIMEOUT) remove=1;
  if(remove==1){
    for(j=i+1;j<cache->size;j++) cache->entries[j-1]=cache->entries[j];
    cache->size--; i--;
    }
  }
}

//
// Find entry in ND cache
//

static ND_cache_entry *icmpv6NDSearchInCache(EthernetAddress ethernet,IPv6Address ip){
int i;
icmp6NDCachePurge();
if(cache!=NULL)
  for(i=0;i<cache->size;i++){
    ND_cache_entry *entry=cache->entries+i;
    if((!ethernetCompare(ethernet,ETHERNET_ADDRESS_NULL) &&
        ethernetCompare(ethernet,entry->ethernet)) ||
       (!ipv6Compare(ip,IPV6_ADDRESS_NULL) &&
        ipv6Compare(ip,entry->ipv6)))
      return entry;
    }
return NULL;
}

//
// Add entry to ARP cache
//

static void icmpv6NDAddToCache(
  IPv6Address ip,EthernetAddress ethernet,unsigned char flags){
time_t now=time(NULL);
icmp6NDCachePurge();
if(cache==NULL){
  cache=(ND_cache *)malloc(sizeof(ND_cache));
  if(cache==NULL){ perror("icmpv6NDAddToCache.malloc"); return; }
  cache->allocated=0;
  cache->size=0;
  cache->entries=NULL;
  }
ND_cache_entry *entry=icmpv6NDSearchInCache(ETHERNET_ADDRESS_NULL,ip);
if(entry!=NULL){
  if(!ethernetCompare(ethernet,ETHERNET_ADDRESS_NULL))
    eventsWake(&(entry->ipv6),sizeof(IPv6Address));
  entry->type=((flags&ND_ADD_STATIC)==0)?ND_ENTRY_DYNAMIC:ND_ENTRY_STATIC;
  entry->ethernet=ethernet;
  entry->timestamp=now;
  goto icmpv6NDAddToCacheExit;
  }
if((flags&ND_ADD_FORCED)==0 && (flags&ND_ADD_STATIC)==0)
  goto icmpv6NDAddToCacheExit;
int i=cache->size;
if(i>=cache->allocated){
  int newsize=(cache->allocated+ND_CACHE_BLOCK_SIZE)*sizeof(ND_cache_entry);
  ND_cache_entry *newent=(ND_cache_entry *)_realloc(cache->entries,newsize);
  if(newent==NULL){ perror("icmpv6NDAddToCache.realloc"); return; }
  cache->allocated += ND_CACHE_BLOCK_SIZE;
  cache->entries=newent;
  }
cache->size++;
cache->entries[i].type=((flags&ND_ADD_STATIC)==0)?ND_ENTRY_DYNAMIC:ND_ENTRY_STATIC;
cache->entries[i].ipv6=ip;
cache->entries[i].ethernet=ethernet;
cache->entries[i].timestamp=now;
if(ethernetCompare(ethernet,ETHERNET_ADDRESS_NULL)){
  // Creation of an incomplete entry
  if(NDEvent<0){
    NDEvent=eventsCreate(0,NULL);
    eventsAddAction(NDEvent,icmpv6NDAction,0);
    }
  char *data=(char *)malloc(sizeof(IPv6Address));
  if(data==NULL){ perror("icmpv6NDAddToCache.malloc"); return; }
  memcpy(data,&ip,sizeof(IPv6Address));
  eventsSchedule(NDEvent,ND_ANSWER_TIMEOUT,data);
  }

icmpv6NDAddToCacheExit:

#ifdef VERBOSE
icmpv6NDDisplayCache(stderr);
#endif
return;
}

//
// Interfaces for searches in ND cache
//

unsigned char icmpv6NDFindMaterial(void *material,void *logical){
EthernetAddress *ethernet=(EthernetAddress *)material;
IPv6Address *ip=(IPv6Address *)logical;
ND_cache_entry *entry=icmpv6NDSearchInCache(ETHERNET_ADDRESS_NULL,*ip);
if(entry!=NULL && !ethernetCompare(entry->ethernet,ETHERNET_ADDRESS_NULL))
  { *ethernet=entry->ethernet; return 1; }
return 0;
}

//
// Action used by ND event
//

static unsigned char icmpv6NDAction(EventsEvent *event,EventsSelector *selector){
eventsWake(selector->data_this,sizeof(IPv4Address));
free(selector->data_this);
return 0;
}
