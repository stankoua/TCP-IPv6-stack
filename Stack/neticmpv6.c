/*
 * Code for ICMPv6 protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "neticmpv6.h"
#include "stack.h"

////
// Local constants
////

#define ICMPV6_HOP_LIMIT	255

////
// Global variables
////

////
// Prototypes
////

////
// Functions
////

#ifdef VERBOSE
//
// Display ICMPv6 packet
//

#define	MAX_BYTES_BY_ROW	16
void displayICMPv6Packet(FILE *output,ICMPv6_fields *icmp,int size){
fprintf(output,"ICMPv6 Type: %02x\n",icmp->type);
fprintf(output,"ICMPv6 Code: %02x\n",icmp->code);
fprintf(output,"ICMPv6 Checksum: %04x\n",icmp->checksum);
fprintf(output,"ICMPv6 Data:\n  ");
int i;
int data_size=size-sizeof(ICMPv6_fields)+1;
for(i=0;i<data_size;i++){
  fprintf(output,"%02hhx ",icmp->data[i]);
  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
    fprintf(output,"\n");
    if(i<data_size-1) fprintf(output,"  ");
    }
  }
if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
}

void displayICMPv6Options(FILE *output,unsigned char *options,int size){
int i;
unsigned char *p=options;
while(p-options<size){
  ICMPv6_option *option=(ICMPv6_option *)p;
  if(option->length>0){
    int len=8*option->length;
    switch(option->type){
      case ICMPV6_OPTION_TYPE_LLASOURCE:
        fprintf(output,"ICMPv6 Option Address Source:\n  ");
        for(i=2;i<len;i++) fprintf(output,"%02x ",p[i]);
        fprintf(output,"\n");
        break;
      case ICMPV6_OPTION_TYPE_LLATARGET:
        fprintf(output,"ICMPv6 Option Address Target:\n  ");
        for(i=2;i<len;i++) fprintf(output,"%02x ",p[i]);
        fprintf(output,"\n");
        break;
      case ICMPV6_OPTION_TYPE_PREFIX:{
        unsigned char l=ICMPv6OptPrefix_get_link(option);
        unsigned char a=ICMPv6OptPrefix_get_auto(option);
        fprintf(output,"ICMPv6 Option Prefix Length: %d\n",option->data.s_prefix.length);
        fprintf(output,"ICMPv6 Option Prefix Flags: %c%c\n",
                       l?'L':'_',a?'A':'_');
        fprintf(output,"ICMPv6 Option Prefix Valid Lifetime: %d\n",
                       option->data.s_prefix.vlifetime);
        fprintf(output,"ICMPv6 Option Prefix Prefered Lifetime: %d\n",
                       option->data.s_prefix.plifetime);
        fprintf(output,"ICMPv6 Option Prefix IPv6 Network: %s\n",
                       ipv6Address2String(option->data.s_prefix.prefix));
        }
        break;
      case ICMPV6_OPTION_TYPE_HEADER:
        fprintf(output,"ICMPv6 Option Redirect Header:\n  ");
        for(i=16;i<len;i++){
          fprintf(output,"%02x ",p[i]);
          if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
            fprintf(output,"\n");
            if(i<len-1) fprintf(output,"  ");
            }
          }
        if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
        break;
      case ICMPV6_OPTION_TYPE_MTU:
        fprintf(output,"ICMPv6 Option MTU: %d\n",option->data.mtu);
        break;
      }
    p += len;
    }
  else break;
  }
} 
#endif

//
// Decode ICMPv6 packet
//

unsigned char icmpv6DecodePacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ifid",0)<0 || arraysTestIndex(infos,"l3id",0)<0 ||
   arraysTestIndex(infos,"lsrc",0)<0 || arraysTestIndex(infos,"data",0)<0 ||
   arraysTestIndex(infos,"iph",0)<0 || arraysTestIndex(infos,"hsum",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_MGETVAR(infos,ifid,int);
AARRAY_MGETVAR(infos,l3id,int);
AARRAY_FGETREF(infos,lsrc,unsigned char *,source,size_address);
AARRAY_FGETREF(infos,data,unsigned char *,data,size);
AARRAY_FGETREF(infos,iph,unsigned char *,iph,size_headers);
AARRAY_FGETVAR(infos,hsum,unsigned short int,csum_headers);
arraysFreeArray(infos);
free(iph);
unsigned short int checksum=genericChecksum(data,size,csum_headers);
if(checksum!=0){ free(data); free(source); return 0; }
ICMPv6_fields *icmp=(ICMPv6_fields *)data;
#ifdef VERBOSE
fprintf(stderr,"Incoming ICMPv6 packet:\n");
displayICMPv6Packet(stderr,icmp,size);
#endif
int size_header=sizeof(ICMPv6_fields)-1;
int size_data=size-size_header;
switch(icmp->type){
  case ICMPV6_TYPE_ECHO_REQUEST:{
    StackLayers *picmp=stackFindLayerByProtocol(LEVEL_CONTROL_IPV6,IPV6_PROTOCOL_ICMP);
    if(picmp!=NULL && picmp->event_out>=0){
      unsigned char type=ICMPV6_TYPE_ECHO_REPLY;
      unsigned char code=ICMPV6_CODE_NONE;
      memmove(data,data+size_header,size_data);
      data=(unsigned char *)_realloc(data,size_data);
      if(data==NULL && size_data>0)
        { perror("icmpv6DecodePacket.realloc"); return 0; }
      AssocArray *icmp_infos=NULL;
      AARRAY_MSETVAR(icmp_infos,ifid);
      AARRAY_MSETVAR(icmp_infos,l3id);
      AARRAY_MSETVAR(icmp_infos,type);
      AARRAY_MSETVAR(icmp_infos,code);
      AARRAY_FSETREF(icmp_infos,data,data,size_data);
      AARRAY_FSETREF(icmp_infos,ldst,source,size_address);
      if(eventsTrigger(picmp->event_out,icmp_infos)<0){
        fprintf(stderr,"Cannot trigger ICMPv6 out event !\n");
        exit(-1);
        }
      }
    else{ free(data); free(source); }
    }
    break;
  case ICMPV6_TYPE_NEIGHBOR_SOLICITATION:
  case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:{
    StackLayers *picmpnd=stackFindLayerByProtocol(
                           LEVEL_CONTROL_IPV6,ICMPV6_LEVEL_NEIGHBOR_DISCOVERY);
    if(picmpnd!=NULL && picmpnd->event_in>=0){
      unsigned short int save_type=icmp->type;
      memmove(data,data+size_header,size_data);
      data=(unsigned char *)_realloc(data,size_data);
      if(data==NULL && size_data>0)
        { perror("icmpv6DecodePacket.realloc"); return 0; }
      AssocArray *icmpnd_infos=NULL;
      AARRAY_MSETVAR(icmpnd_infos,ifid);
      AARRAY_MSETVAR(icmpnd_infos,l3id);
      AARRAY_FSETVAR(icmpnd_infos,type,save_type);
      AARRAY_FSETREF(icmpnd_infos,data,data,size_data);
      AARRAY_FSETREF(icmpnd_infos,lsrc,source,size_address);
      if(eventsTrigger(picmpnd->event_in,icmpnd_infos)<0){
        fprintf(stderr,"Cannot trigger ICMPv6 ND in event !\n");
        exit(-1);
        }
      }
    }
    break;
  default:
    free(data); free(source);
    break;
  }
return 0;
}

//
// Send ICMPv6 packet
//

unsigned char icmpv6SendPacket(EventsEvent *event,EventsSelector *selector){

/* Get packet data */
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ifid",0)<0 || arraysTestIndex(infos,"l3id",0)<0 ||
   arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"data",0)<0 ||
   arraysTestIndex(infos,"type",0)<0 || arraysTestIndex(infos,"code",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_MGETVAR(infos,ifid,int);
AARRAY_MGETVAR(infos,l3id,int);
AARRAY_FGETREF(infos,ldst,unsigned char *,target,size_address);
AARRAY_FGETREF(infos,data,unsigned char *,data,size_data);
AARRAY_MGETVAR(infos,type,unsigned char);
AARRAY_MGETVAR(infos,code,unsigned char);
arraysFreeArray(infos);

/* Get underlying protocol */
StackLayers *pip=stackFindLayerByIdentity(l3id);
if(pip==NULL || pip->event_out<0)
  { free(data); free(target); return 0; }

/* Build ICMPv6 packet */
int size_headers=sizeof(ICMPv6_fields)-1;
int size_icmp=size_headers+size_data;
data=(unsigned char *)_realloc(data,size_icmp);
if(data==NULL && size_icmp>0)
  { free(target); perror("icmpSendPacket.realloc"); return 0; }
memmove(data+size_headers,data,size_data);
bzero(data,size_headers);
ICMPv6_fields *icmp=(ICMPv6_fields *)data;
icmp->type=type;
icmp->code=code;
icmp->checksum=0;
int checksum_offset=offsetof(ICMPv6_fields,checksum);
#ifdef VERBOSE
fprintf(stderr,"Outgoing ICMPv6 packet:\n");
displayICMPv6Packet(stderr,icmp,size_icmp);
#endif
unsigned char protocol=IPV6_PROTOCOL_ICMP;
AssocArray *ip_options=NULL;
int hop=ICMPV6_HOP_LIMIT;
AARRAY_MSETVAR(ip_options,hop);
int size_options=arraysGetSize(ip_options);
AssocArray *ip_infos=NULL;
AARRAY_MSETVAR(ip_infos,ifid);
AARRAY_MSETVAR(ip_infos,l3id);
AARRAY_FSETREF(ip_infos,ldst,target,size_address);
AARRAY_FSETVAR(ip_infos,proto,protocol);
AARRAY_FSETREF(ip_infos,data,data,size_icmp);
AARRAY_FSETREF(ip_infos,opts,ip_options,size_options);
AARRAY_FSETVAR(ip_infos,ofcs,checksum_offset);
if(eventsTrigger(pip->event_out,ip_infos)<0){
  fprintf(stderr,"Cannot trigger IP out event !\n");
  exit(-1);
  }
return 0;
}
