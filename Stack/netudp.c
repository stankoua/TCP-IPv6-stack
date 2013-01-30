/*
 * Code for UDP protocol implementation
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
#include "netudp.h"
#include "stack.h"

////
// Global variables
////

////
// Functions
////

#ifdef VERBOSE
//
// Display UDP packet
//

#define	MAX_BYTES_BY_ROW	16
void displayUDPPacket(FILE *output,UDP_fields *udp,int size){
fprintf(output,"UDP Port source: %04x\n",ntohs(udp->source));
fprintf(output,"UDP Port target: %04x\n",ntohs(udp->target));
fprintf(output,"UDP Checksum: %04x\n",ntohs(udp->checksum));
fprintf(output,"UDP Data:\n  ");
int i;
int data_size=size-sizeof(UDP_fields)+1;
for(i=0;i<data_size;i++){
  fprintf(output,"%02hhx ",udp->data[i]);
  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
    fprintf(output,"\n");
    if(i<data_size-1) fprintf(output,"  ");
    }
  }
if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
}
#endif

//
// Decode UDP packet
//

unsigned char udpDecodePacket(EventsEvent *event,EventsSelector *selector){
/* Get values from associative array */
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"iph",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_FGETREF(infos,data,unsigned char *,data,size);
AARRAY_HGETREF(infos,iph,IPv4_fields *,iph);
arraysFreeArray(infos);

/* Check UDP headers */
UDP_fields *udp=(UDP_fields *)data;
if(ntohs(udp->length)!=size){
#ifdef VERBOSE
  fprintf(stderr,"UDP packet: bad length\n");
#endif
  free(data); free(iph); return 0;
  }
if(udp->checksum!=0){
  int sum=pseudoHeaderChecksum(
    iph->source,iph->target,IPV4_PROTOCOL_UDP,&data,size);
  if(sum<0){ free(data); free(iph); return 0; }
  unsigned short int checksum=(unsigned short int)sum;
  udp=(UDP_fields *)data;
  if(checksum!=0){
#ifdef VERBOSE
    fprintf(stderr,"UDP packet: bad checksum\n");
#endif
    free(data); free(iph); return 0;
    }
  }
int psource_net=udp->source;
int ptarget_net=udp->target;
int psource=ntohs(udp->source);
int ptarget=ntohs(udp->target);
if(psource==0){
#ifdef VERBOSE
  fprintf(stderr,"UDP packet: bad source port\n");
#endif
  free(data); free(iph); return 0;
  }
if(ptarget==0){
#ifdef VERBOSE
  fprintf(stderr,"UDP packet: bad destination port\n");
#endif
  free(data); free(iph); return 0;
  }
#ifdef VERBOSE
fprintf(stderr,"Incoming UDP packet:\n");
displayUDPPacket(stderr,udp,size);
#endif

/* Process UDP data */
unsigned char status=0;
StackProcess *process=
  stackFindProcess(IPV4_PROTOCOL_UDP,iph->target,ptarget);
if(process==NULL){
  StackLayers *picmp=stackFindLayerByProtocol(LEVEL_TRANSPORT,IPV4_PROTOCOL_ICMP);
  if(picmp!=NULL && picmp->event_out>=0){
    unsigned char type=ICMPV4_TYPE_UNREACHABLE;
    unsigned char code=ICMPV4_UNREACHABLE_CODE_PORT;
    int size_iph=IPv4_get_hlength(iph)*4;
    int size_hudp=2*4;
    int size_reply=4+size_iph+size_hudp;
    data=(unsigned char *)_realloc(data,size_reply);
    if(data==NULL && size_reply>0)
      { perror("udpDecodePacket.realloc"); return 0; }
    memmove(data+4+size_iph,data,size_hudp);
    memcpy(data+4,iph,size_iph);
    bzero(data,4);
    AssocArray *icmp_infos=NULL;
    AARRAY_MSETVAR(icmp_infos,type);
    AARRAY_MSETVAR(icmp_infos,code);
    AARRAY_FSETREF(icmp_infos,data,data,size_reply);
    AARRAY_FSETVAR(icmp_infos,ldst,iph->source);
    if(eventsTrigger(picmp->event_out,icmp_infos)<0){
      fprintf(stderr,"Cannot trigger ICMP out event !\n");
      exit(-1);
      }
    }
  else free(data);
  }
else{
  int size_hdr=sizeof(UDP_fields)-1;
  int size_data=size-size_hdr;
  memmove(data,data+size_hdr,size_data);
  data=(unsigned char *)_realloc(data,size_data);
  if(data==NULL && size_data>0){ perror("udpDecodePacket.realloc"); return 0; }
  unsigned char type=PROCESS_DATA;
  AssocArray *infos=NULL;
  AARRAY_MSETVAR(infos,type);
  AARRAY_FSETVAR(infos,ldst,iph->target);
  AARRAY_FSETVAR(infos,lsrc,iph->source);
  AARRAY_FSETVAR(infos,pdst,ptarget_net);
  AARRAY_FSETVAR(infos,psrc,psource_net);
  AARRAY_FSETREF(infos,data,data,size_data);
  if(eventsTrigger(process->event,infos)<0){
    fprintf(stderr,"Cannot trigger process event (UDP DATA) !\n");
    exit(-1);
    }

  }
free(iph);
return status;
}

//
// Send UDP packet
//

unsigned char udpSendPacket(EventsEvent *event,EventsSelector *selector){
/* Get values from associative array */
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"pdst",0)<0 ||
   arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"psrc",0)<0)
  { arraysFreeArray(infos); return 1; }
StackLayers *pip=stackFindLayerByProtocol(LEVEL_NETWORK,ETHERNET_PROTO_IP);
if(pip==NULL || pip->event_out<0){ arraysFreeArray(infos); return 0; }
AARRAY_FGETVAR(infos,ldst,IPv4Address,target);
AARRAY_MGETVAR(infos,pdst,unsigned short int);
AARRAY_MGETVAR(infos,psrc,unsigned short int);
AARRAY_FGETREF(infos,data,unsigned char *,data,size_data);
arraysFreeArray(infos);

/* Fill UDP headers */
IPv4Address source=IPV4_ADDRESS_NULL;
EthernetInterface *device=stackFindEthernetDeviceByIPv4Network(target);
if(device!=NULL) source=device->IPv4[0].address;
int size_hudp=sizeof(UDP_fields)-1;
int size_udp=size_data+size_hudp;
data=(unsigned char *)_realloc(data,size_udp);
if(data==NULL && size_udp>0){ perror("udpSendPacket.realloc"); return 0; }
memmove(data+size_hudp,data,size_data);
bzero(data,size_hudp);
UDP_fields *udp=(UDP_fields *)data;
udp->source=htons(psrc);
udp->target=htons(pdst);
udp->length=htons(size_udp);
int sum=pseudoHeaderChecksum(
  source,target,IPV4_PROTOCOL_UDP,&data,size_udp);
if(sum<0){ free(data); return 0; }
unsigned short int checksum=(unsigned short int)sum;
udp=(UDP_fields *)data;
udp->checksum=htons(checksum);
#ifdef VERBOSE
fprintf(stderr,"Outgoing UDP packet:\n");
displayUDPPacket(stderr,udp,size_udp);
#endif

/* Call IP layer */
unsigned char protocol=IPV4_PROTOCOL_UDP;
AssocArray *ip_options=NULL;
AARRAY_FSETVAR(ip_options,lsrc,source);
int size_options=arraysGetSize(ip_options);
AssocArray *ip_infos=NULL;
AARRAY_FSETVAR(ip_infos,ldst,target);
AARRAY_FSETVAR(ip_infos,proto,protocol);
AARRAY_FSETREF(ip_infos,data,data,size_udp);
AARRAY_FSETREF(ip_infos,opts,ip_options,size_options);
if(eventsTrigger(pip->event_out,ip_infos)<0){
  fprintf(stderr,"Cannot trigger IP out event !\n");
  exit(-1);
  }

return 0;
}
