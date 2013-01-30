/*
 * Code for ICMP protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "neticmp.h"
#include "stack.h"

////
// Global variables
////

////
// Functions
////

#ifdef VERBOSE
//
// Display ICMPv4 packet
//

#define	MAX_BYTES_BY_ROW	16
void displayICMPv4Packet(FILE *output,ICMPv4_fields *icmp,int size){
fprintf(output,"ICMP Type: %02x\n",icmp->type);
fprintf(output,"ICMP Code: %02x\n",icmp->code);
fprintf(output,"ICMP Checksum: %04x\n",icmp->checksum);
fprintf(output,"ICMP Data:\n  ");
int i;
int data_size=size-sizeof(ICMPv4_fields)+1;
for(i=0;i<data_size;i++){
  fprintf(output,"%02hhx ",icmp->data[i]);
  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
    fprintf(output,"\n");
    if(i<data_size-1) fprintf(output,"  ");
    }
  }
if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
}
#endif

//
// Decode ICMPv4 packet
//

unsigned char icmpDecodePacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"iph",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_FGETREF(infos,data,unsigned char *,data,size);
AARRAY_HGETREF(infos,iph,IPv4_fields *,iph);
arraysFreeArray(infos);
IPv4Address source=iph->source;
IPv4Address target=iph->target;
free(iph);
unsigned short int checksum=genericChecksum(data,size,0);
if(checksum!=0){ free(data); return 0; }
ICMPv4_fields *icmp=(ICMPv4_fields *)data;
#ifdef VERBOSE
fprintf(stderr,"Incoming ICMPv4 packet:\n");
displayICMPv4Packet(stderr,icmp,size);
#endif
int len_header=sizeof(ICMPv4_fields)-1;
int len_data=size-len_header;
switch(icmp->type){
  case ICMPV4_TYPE_ECHO_REQUEST:{
    StackLayers *picmp=stackFindLayerByProtocol(LEVEL_CONTROL_IPV4,IPV4_PROTOCOL_ICMP);
    if(picmp!=NULL && picmp->event_out>=0){
      unsigned char type=ICMPV4_TYPE_ECHO_REPLY;
      unsigned char code=ICMPV4_CODE_NONE;
      memmove(data,data+len_header,len_data);
      data=(unsigned char *)_realloc(data,len_data);
      if(data==NULL && len_data>0)
        { perror("icmpDecodePacket.realloc"); return 0; }
      AssocArray *icmp_infos=NULL;
      AARRAY_MSETVAR(icmp_infos,type);
      AARRAY_MSETVAR(icmp_infos,code);
      AARRAY_FSETREF(icmp_infos,data,data,len_data);
      AARRAY_FSETVAR(icmp_infos,ldst,source);
      if(eventsTrigger(picmp->event_out,icmp_infos)<0){
        fprintf(stderr,"Cannot trigger ICMP out event !\n");
        exit(-1);
        }
      }
    else free(data);
    }
    break;
  case ICMPV4_TYPE_MASK_REQUEST:{
    StackLayers *picmp=stackFindLayerByProtocol(LEVEL_CONTROL_IPV4,IPV4_PROTOCOL_ICMP);
    if(picmp==NULL || picmp->event_out<0){ free(data); break; }
    if(len_data!=8){ free(data); break; }
    EthernetInterface *device=stackFindEthernetDeviceByIPv4(target);
    if(device==NULL){ free(data); break; }
    unsigned char type=ICMPV4_TYPE_MASK_REPLY;
    unsigned char code=ICMPV4_CODE_NONE;
    memmove(data,data+len_header,len_data);
    data=(unsigned char *)_realloc(data,len_data);
    if(data==NULL && len_data>0)
      { perror("icmpDecodePacket.realloc"); return 0; }
    IPv4Address mask=ipNetmask(device->IPv4[0].netmask);  
    memcpy(data+4,(unsigned char *)&mask,4);
    AssocArray *icmp_infos=NULL;
    AARRAY_MSETVAR(icmp_infos,type);
    AARRAY_MSETVAR(icmp_infos,code);
    AARRAY_FSETREF(icmp_infos,data,data,len_data);
    AARRAY_FSETVAR(icmp_infos,ldst,source);
    if(eventsTrigger(picmp->event_out,icmp_infos)<0){
      fprintf(stderr,"Cannot trigger ICMP out event !\n");
      exit(-1);
      }
    }
    break;
  default:
    free(data);
    break;
  }
return 0;
}

//
// Send ICMPv4 packet
//

unsigned char icmpSendPacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"type",0)<0 || arraysTestIndex(infos,"code",0)<0 ||
   arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"ldst",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_MGETVAR(infos,type,unsigned char);
AARRAY_MGETVAR(infos,code,unsigned char);
AARRAY_FGETREF(infos,data,unsigned char *,data,size_data);
AARRAY_FGETVAR(infos,ldst,IPv4Address,target);
arraysFreeArray(infos);

/* Get underlying protocol */
StackLayers *pip=stackFindLayerByProtocol(LEVEL_NETWORK,ETHERNET_PROTO_IP);
if(pip==NULL || pip->event_out<0){ free(data); return 0; }

/* Build ICMP packet */
int size_headers=sizeof(ICMPv4_fields)-1;
int size_icmp=size_headers+size_data;
data=(unsigned char *)_realloc(data,size_icmp);
if(data==NULL && size_icmp>0){ perror("icmpSendPacket.realloc"); return 0; }
memmove(data+size_headers,data,size_data);
bzero(data,size_headers);
ICMPv4_fields *icmp=(ICMPv4_fields *)data;
icmp->type=type;
icmp->code=code;
icmp->checksum=htons(genericChecksum(data,size_icmp,0));
#ifdef VERBOSE
fprintf(stderr,"Outgoing ICMPv4 packet:\n");
displayICMPv4Packet(stderr,icmp,size_icmp);
#endif
unsigned char protocol=IPV4_PROTOCOL_ICMP;
AssocArray *ip_options=NULL;
int size_options=arraysGetSize(ip_options);
AssocArray *ip_infos=NULL;
AARRAY_FSETVAR(ip_infos,ldst,target);
AARRAY_FSETVAR(ip_infos,proto,protocol);
AARRAY_FSETREF(ip_infos,data,data,size_icmp);
AARRAY_FSETREF(ip_infos,opts,ip_options,size_options);
if(eventsTrigger(pip->event_out,ip_infos)<0){
  fprintf(stderr,"Cannot trigger IP out event !\n");
  exit(-1);
  }
return 0;
}
