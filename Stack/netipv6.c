/*
 * Code for IPv6 protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "neticmpv6.h"
#include "stack.h"
#include "netroute.h"

////
// Global variables
////

IPv6Address IPV6_ADDRESS_NULL={{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};

IPv6Address IPV6_PREFIX_NODE={{0xff,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
IPv6Address IPV6_PREFIX_LINK={{0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
IPv6Address IPV6_PREFIX_SITE={{0xff,0x05,0x00,0x00,0x00,0x00,0x00,0x00,
                               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};

IPv6Address IPV6_PREFIX_ND={{0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                             0x00,0x00,0x00,0x01,0xff,0x00,0x00,0x00}};

IPv6Address IPV6_SUFFIX_HOSTS={{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01}};
IPv6Address IPV6_SUFFIX_ROUTERS={{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02}};

static int IPv6_header_codes[]={
  IPV6_HEADER_HOPBYHOP,IPV6_HEADER_ROUTAGE,IPV6_HEADER_FRAGMENT,IPV6_HEADER_AUTHENTICATION,
  IPV6_HEADER_ENCRYPTION,IPV6_HEADER_DESTINATION,IPV6_HEADER_MOBILITY,IPV6_HEADER_END,-1
  };

////
// Prototypes
////

static unsigned char ipv6HeaderIsProtocol(int code);
static unsigned char ipv6AnalyzeHeaders(
  IPv6_fields *ip,int *size_headers,int *protocol);

////
// Functions
////

//
// Display IPv6 packet
//

#ifdef VERBOSE
#define	MAX_BYTES_BY_ROW	16
void displayIPv6Packet(FILE *output,IPv6_fields *ip,int size){
int i;
fprintf(output,"IPv6 Version: %d\n",IPv6_get_version(ip));
fprintf(output,"IPv6 Traffic Class: %02x\n",IPv6_get_traffic(ip));
fprintf(output,"IPv6 Flow Label: %05x\n",IPv6_get_flow(ip));
fprintf(output,"IPv6 Payload Length: %d\n",ntohs(ip->length));
fprintf(output,"IPv6 Next Header: %02x\n",ip->next);
fprintf(output,"IPv6 Hop Count: %d\n",ip->hop);
fprintf(output,"IPv6 Source: %s\n",ipv6Address2String(ip->source));
fprintf(output,"IPv6 Target: %s\n",ipv6Address2String(ip->target));
int length=ntohs(ip->length);
int position=sizeof(IPv6_fields)-1;
unsigned char *raw=(unsigned char *)ip+position;
int hcode=ip->next;
while(!ipv6HeaderIsProtocol(hcode)){
  IPv6_header *header=(IPv6_header *)raw;
  hcode=header->next;
  int hlen=header->length;
  fprintf(output,"IPv6 Header, Next Header: %02x\n",hcode);
  fprintf(output,"IPv6 Header, Length: %d\n",hlen);
  raw += 2;
  int rlen=hlen+6;
  if(rlen>0) fprintf(output,"  ");
  for(i=0;i<rlen;i++){
    fprintf(output,"%02x ",*(raw++));
    if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
      fprintf(output,"\n");
      if(i<rlen-1) fprintf(output,"  ");
      }
    }
  if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
  }
fprintf(output,"IPv6 Data:\n");
if(length>0) fprintf(output,"  ");
for(i=0;i<length;i++){
  fprintf(output,"%02x ",*(raw++));
  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
    fprintf(output,"\n");
    if(i<length-1) fprintf(output,"  ");
    }
  }
if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
}
#endif

//
// Initialize IPv6 protocol
//

unsigned char ipv6Initialize(AssocArray *infos){
if(arraysTestIndex(infos,"intf",0)<0){ arraysFreeArray(infos); return 0; }
AARRAY_MGETVAR(infos,intf,GenericInterface *);
arraysFreeArray(infos);
// Check that interface type is Ethernet
if(intf->type!=INTERFACE_TYPE_ETHERNET) return 0;
EthernetInterface *ether_intf=(EthernetInterface *)intf;
// Add multicast Ethernet addresses
int i,j;
if(ether_intf->ether_multicast!=NULL){
  EthernetAddress address=ETHERNET_ADDRESS_BROADCASTV6;
  address.bytes[ETHERNET_ADDRESS_SIZE-1]=0x01;
  if(!stackAddEthernetMulticast(ether_intf->ether_multicast,address)){
    fprintf(stderr,"Cannot add IPv6 broadcast Ethernet address to multicast list!\n");
    return 0;
    }
  i=0;
  while(!ipv6Compare(ether_intf->IPv6[i].address,IPV6_ADDRESS_NULL)){
    EthernetAddress address=ETHERNET_ADDRESS_BROADCASTV6;
    address.bytes[ETHERNET_ADDRESS_SIZE-4]=0xff;
    for(j=0;j<3;j++)
      address.bytes[ETHERNET_ADDRESS_SIZE-j-1]=
        ether_intf->IPv6[i].address.bytes[IPV6_ADDRESS_SIZE-j-1];
    if(!stackAddEthernetMulticast(ether_intf->ether_multicast,address)){
      fprintf(stderr,"Cannot add IPv6 ND Ethernet address to multicast list!\n");
      return 0;
      }
    i++;
    }
  }
// Create multicast IPv6 addresses
if(ether_intf->IPv6_multicast==NULL){
  ether_intf->IPv6_multicast=(IPv6MulticastAddresses *)
    calloc(1,sizeof(IPv6MulticastAddresses));
  if(ether_intf->IPv6_multicast==NULL)
    { perror("ipv6Initialize.calloc(multicast)"); return 0; }
  IPv6Address *scopes[]={&IPV6_PREFIX_NODE,&IPV6_PREFIX_LINK,&IPV6_PREFIX_SITE,NULL};
  IPv6Address *suffixes[]={&IPV6_SUFFIX_HOSTS,NULL};
  IPv6Address **scope=scopes;
  while(*scope!=NULL){
    IPv6Address **suffix=suffixes;
    while(*suffix!=NULL){
      IPv6Address multicast;
      for(i=0;i<IPV6_ADDRESS_SIZE;i++)
        multicast.bytes[i]=((*scope)->bytes[i])|((*suffix)->bytes[i]);
      if(!stackAddIPv6Multicast(ether_intf->IPv6_multicast,multicast)){
        fprintf(stderr,"Cannot add constant IPv6 multicast to multicast list!\n");
        return 0;
        }
      suffix++;
      }
    scope++;
    }
  i=0;
  IPv6Address multicast=IPV6_PREFIX_ND;
  while(!ipv6Compare(ether_intf->IPv6[i].address,IPV6_ADDRESS_NULL)){
    IPv6Address *mine=&(ether_intf->IPv6[i].address);
    for(j=0;j<3;j++)
      multicast.bytes[IPV6_ADDRESS_SIZE-j-1]=mine->bytes[IPV6_ADDRESS_SIZE-j-1];
printf("IPV6=%s\n",ipv6Address2String(multicast));
    if(!stackAddIPv6Multicast(ether_intf->IPv6_multicast,multicast)){
      fprintf(stderr,"Cannot add ND IPv6 multicast to multicast list!\n");
      return 0;
      }
    i++;
    }
  }
return 1;
}


//
// Decode IPv6 packet
//

static unsigned char ipv6AnalyzeHeaders(IPv6_fields *ip,int *size_headers,int *protocol)
{
    /* TODO: handle optional headers */
    unsigned char result=1;
    int position=sizeof(IPv6_fields)-1;
    unsigned char *raw=(unsigned char *)ip+position;
    int hcode=ip->next;
    while(!ipv6HeaderIsProtocol(hcode)){
        IPv6_header *header=(IPv6_header *)raw;
        hcode=header->next;
        int hlen=header->length;
        result=0; 
        raw += (hlen+8);
    }
    if(size_headers!=NULL) *size_headers=raw-(unsigned char *)ip;
    *protocol=hcode;
    return result;
}

unsigned char ipv6DecodePacket(EventsEvent *event,EventsSelector *selector)
{
    StackLayers *this=(StackLayers *)event->data_init;    // network level
    AssocArray *infos=(AssocArray *)selector->data_this;  
    // If tab contents nothing
    if(arraysTestIndex(infos,"ifid",0)<0 || arraysTestIndex(infos,"data",0)<0)
        { arraysFreeArray(infos); return 1; }
    AARRAY_MGETVAR(infos,ifid,int);
    AARRAY_FGETREF(infos,data,unsigned char *,data,size);  // int size = size(data)
    arraysFreeArray(infos);
    IPv6_fields *ip=(IPv6_fields *)data;
    if((stackFindEthernetDeviceByIPv6(ip->target)==NULL) &&
       (stackFindEthernetDeviceByIPv6Multicast(ip->target)==NULL)){
#ifdef VERBOSE
        fprintf(stderr,"IPv6 packet: not for us !\n");
#endif
        free(data); return 0;
    }
#ifdef VERBOSE
    if(ip->hop==0){
#ifdef VERBOSE
        fprintf(stderr,"IPv6 packet: zero Hop Count !\n");
#endif
        free(data); return 0;
    }
    int size_headers;
    int protocol;
    if(!ipv6AnalyzeHeaders(ip,&size_headers,&protocol)){
#ifdef VERBOSE
        fprintf(stderr,"IPv6 packet: unknown header !\n");
#endif
        free(data); return 0;
    }
    int size_data=ntohs(ip->length);
    if(size!=size_headers+size_data){
#ifdef VERBOSE
        fprintf(stderr,"IPv6 packet: bad size !\n");
#endif
        free(data); return 0;
    }
    fprintf(stderr,"Incoming IPv6 packet:\n");
    displayIPv6Packet(stderr,ip,size);
#endif
    int size_address=sizeof(IPv6Address);
    unsigned char *source=(unsigned char *)malloc(size_address);
    if(source==NULL)
        { free(data); perror("ipv6DecodePacket.malloc(lsrc)"); return 0; }
    memcpy(source,&(ip->source),size_address);
    StackLayers *layer=stackFindLayerByProtocol(LEVEL_CONTROL_IPV6,protocol);
    if(layer==NULL) layer=stackFindLayerByProtocol(LEVEL_TRANSPORT_IPV6,protocol);  // Interesting !!!!!!!!!!!
    if(layer!=NULL && layer->event_in>=0){
        unsigned short int checksum=
            ipv6PseudoHeaderChecksum(ip->source,ip->target,size_data,ip->next);
        unsigned char *iph=(unsigned char *)malloc(size_headers);
        if(iph==NULL)
            { free(data); perror("ipv6DecodePacket.malloc(iph)"); return 0; }
        memcpy(iph,data,size_headers);
        memmove(data,data+size_headers,size_data);
        data=(unsigned char *)_realloc(data,size_data);
        if(data==NULL && size_data>0)
            { perror("ipv6DecodePacket.realloc"); return 0; }
        AssocArray *infos=NULL;
        AARRAY_MSETVAR(infos,ifid);
        AARRAY_FSETVAR(infos,l3id,this->identity);
        AARRAY_FSETREF(infos,data,data,size_data);
        AARRAY_FSETREF(infos,lsrc,source,size_address);
        AARRAY_FSETREF(infos,iph,iph,size_headers);
        AARRAY_FSETVAR(infos,hsum,checksum);
        if(eventsTrigger(layer->event_in,infos)<0){
            fprintf(stderr,"Cannot trigger level 4 protocol event !\n");
            exit(-1);
        }
    }
    else{
        StackLayers *picmp=stackFindLayerByProtocol(LEVEL_CONTROL_IPV6,IPV6_PROTOCOL_ICMP);
        if(picmp!=NULL && picmp->event_out>=0){
            unsigned char type=ICMPV6_TYPE_BAD_PARAMETER;
            unsigned char code=ICMPV6_BAD_PARAM_CODE_UNKNOWN_HEADER;
            int reply_size=size_headers+4;
            data=(unsigned char *)_realloc(data,reply_size);
            if(data==NULL && reply_size>0)
            { perror("ipv6DecodePacket.realloc"); return 0; }
            memmove(data+4,data,reply_size-4);
            bzero(data,4);
            AssocArray *icmp_infos=NULL;
            AARRAY_MSETVAR(icmp_infos,ifid);
            AARRAY_FSETVAR(infos,l3id,this->identity);
            AARRAY_MSETVAR(icmp_infos,type);
            AARRAY_MSETVAR(icmp_infos,code);
            AARRAY_FSETREF(icmp_infos,data,data,reply_size);
            AARRAY_FSETREF(icmp_infos,ldst,source,size_address);
            if(eventsTrigger(picmp->event_out,icmp_infos)<0){
                fprintf(stderr,"Cannot trigger ICMPv6 out event !\n");
                exit(-1);
            }
        }
        else{ free(data); free(source); }
    }
    return 0;
}

//
// Send IPv6 packet
//

static int ipv6FillHeaders(
       unsigned char **packet,AssocArray *headers,AssocArray *options){
if(arraysTestIndex(headers,"ldst",0)<0 || arraysTestIndex(headers,"lsrc",0)<0 ||
   arraysTestIndex(headers,"proto",0)<0 || arraysTestIndex(headers,"size",0)<0)
  { arraysFreeArray(options); arraysFreeArray(headers); return -1; }
AARRAY_FGETVAR(headers,ldst,IPv6Address,target);
AARRAY_FGETVAR(headers,lsrc,IPv6Address,source);
AARRAY_FGETVAR(headers,proto,unsigned char,protocol);
AARRAY_FGETVAR(headers,size,int,size_data);
arraysFreeArray(headers);
/* TODO: handle optional headers */
int size_headers=sizeof(IPv6_fields)-1;
int size_packet=size_headers+size_data;
*packet=(unsigned char *)_realloc(*packet,size_packet);
if(*packet==NULL)
  { perror("ipv6FillHeader.realloc"); arraysFreeArray(options); return 0; }
memmove(*packet+size_headers,*packet,size_data);
bzero(*packet,size_headers);
IPv6_fields *ip=(IPv6_fields *)*packet;
IPv6_set_version(ip,IPV6_VERSION);
ip->length=htons(size_data);
ip->target=target;
ip->source=source;
ip->next=protocol;
/* TODO: handle more IPv6 header tuning */
/* TODO: handle IPv6 optional headers   */
if(arraysTestIndex(options,"hop",0)<0) ip->hop=IPV6_DEFAULT_HOP_COUNT;
else { AARRAY_MGETVAR(options,hop,unsigned char); ip->hop=hop; }
arraysFreeArray(options);
return size_packet;
}

unsigned char ipv6SendPacket(EventsEvent *event,EventsSelector *selector){
StackLayers *this=(StackLayers *)event->data_init;

/* Get values from associative array */
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ifid",0)<0 || arraysTestIndex(infos,"l3id",0)<0 ||
   arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"data",0)<0 ||
   arraysTestIndex(infos,"proto",0)<0 || arraysTestIndex(infos,"opts",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_MGETVAR(infos,ifid,int);
AARRAY_MGETVAR(infos,l3id,int);
AARRAY_FGETREF(infos,ldst,unsigned char *,target,size_address);
AARRAY_FGETREF(infos,data,unsigned char *,data,size_data);
AARRAY_FGETVAR(infos,proto,unsigned char,protocol);
AARRAY_HGETREF(infos,opts,AssocArray *,options);

/* Verifications about addresses */
if(size_address!=IPV6_ADDRESS_SIZE){
  free(target); free(data);
  arraysFreeArray(options); arraysFreeArray(infos);
  return 0;
  }
IPv6Address ipv6_target=*((IPv6Address *)target);
free(target);

/* Try to resolve target IPv6 address    */
/* Reschedule packet if resolution fails */ 
EthernetAddress ether_target;
unsigned char resolv=
  stackAddressResolution(MATADDR_ETHERNET,LOGADDR_IPV6,&ether_target,&ipv6_target);
if(!resolv){
  StackLayers *picmpnd=stackFindLayerByProtocol(
                       LEVEL_CONTROL_IPV6,ICMPV6_LEVEL_NEIGHBOR_DISCOVERY);
  if(picmpnd==NULL || picmpnd->event_out<0)
    { free(data); arraysFreeArray(options); arraysFreeArray(infos); return 0; }
  int retrans=0;
  if(arraysTestIndex(infos,"try",0)>=0)
    { AARRAY_MGETVAR(infos,try,int); retrans=try; }
  if(retrans<IPV6_RETRANS_MAX){
    retrans++;
    AARRAY_FSETVAR(infos,try,retrans);
    if(eventsWaitPoint(event->identity,&ipv6_target,size_address,infos)<0){
      fprintf(stderr,"Cannot reschedule IPv6 packet !\n");
      exit(-1);
      }
    unsigned char *copy_addr=malloc(size_address);
    if(copy_addr==NULL){
      free(data); free(options);
      perror("ipv6SendPacket.malloc"); return 0;
      }
    unsigned char *copy_ldst=malloc(size_address);
    if(copy_ldst==NULL){
      free(copy_addr); free(data); free(options);
      perror("ipv6SendPacket.malloc"); return 0;
      }
    memcpy(copy_addr,&ipv6_target,size_address);
    memcpy(copy_ldst,&IPV6_ADDRESS_NULL,size_address);
    unsigned short int type=ICMPV6_TYPE_NEIGHBOR_SOLICITATION;
    AssocArray *icmpnd_infos=NULL;
    AARRAY_MSETVAR(icmpnd_infos,ifid);
    AARRAY_MSETVAR(icmpnd_infos,l3id);
    AARRAY_MSETVAR(icmpnd_infos,type);
    AARRAY_FSETREF(icmpnd_infos,addr,copy_addr,size_address);
    AARRAY_FSETREF(icmpnd_infos,ldst,copy_ldst,size_address);
    if(eventsTrigger(picmpnd->event_out,icmpnd_infos)<0){
      fprintf(stderr,"Cannot trigger ICMPv6 ND out event !\n");
      exit(-1);
      }
#ifdef VERBOSE
    fprintf(stderr,"Queued IPv6 packet to %s.\n",ipv6Address2String(ipv6_target));
#endif
    }
  else{
#ifdef VERBOSE
    fprintf(stderr,"Destroyed IPv6 packet to %s\n",ipv6Address2String(ipv6_target));
    fprintf(stderr,"  -> retransmitted %d times.\n",retrans+1);
#endif
    free(data); arraysFreeArray(options); arraysFreeArray(infos);
    }
  return 0;
  }

/* Do some IPv6 routing */
AssocArray *route_infos=NULL;
if(arraysTestIndex(infos,"ifid",0)<0){
  AARRAY_MGETREF(options,lsrc,unsigned char *);
  AARRAY_MSETREF(route_infos,lsrc);
  }
AARRAY_FSETVAR(route_infos,ifin,ifid);
AssocArray *route_result=
  routeDoRouting(this,(unsigned char *)&ipv6_target,route_infos);
if(route_infos==NULL)
  { free(data); arraysFreeArray(options); arraysFreeArray(infos); }
AARRAY_HGETREF(route_result,lsrc,unsigned char *,source);
AARRAY_MGETVAR(route_result,iout,int); 
arraysFreeArray(route_result);
IPv6Address ipv6_source=*((IPv6Address *)source);
free(source);

/* If needed compute checksum for higher protocol */
if(arraysTestIndex(infos,"ofcs",0)>=0){
  AARRAY_MGETVAR(infos,ofcs,int);
  unsigned short int csum_headers=
    ipv6PseudoHeaderChecksum(ipv6_source,ipv6_target,size_data,protocol);
  unsigned short int csum_packet=
    htons(genericChecksum(data,size_data,csum_headers));
  memcpy(data+ofcs,&csum_packet,sizeof(csum_packet));
  }
arraysFreeArray(infos);

/* Get underlying protocol */
GenericInterface *intf_gen=stackFindDeviceByIdentity(iout);
if(intf_gen==NULL || intf_gen->type!=INTERFACE_TYPE_ETHERNET)
  { free(data); arraysFreeArray(options); return 0; }
EthernetInterface *intf_eth=(EthernetInterface *)intf_gen;
StackLayers *pether=stackFindLayerByProtocol(LEVEL_LINK,0x0000);
if(pether==NULL || pether->event_out<0)
  { free(data); arraysFreeArray(options); return 0; }

/* Fill IPv6 headers          */
AssocArray *headers=NULL;
AARRAY_FSETVAR(headers,ldst,ipv6_target);
AARRAY_FSETVAR(headers,lsrc,ipv6_source);
AARRAY_FSETVAR(headers,proto,protocol);
AARRAY_FSETVAR(headers,size,size_data);
int size=ipv6FillHeaders(&data,headers,options);
if(size<0){ free(data); return 1; }
if(size==0){ free(data); return 0; }
#ifdef VERBOSE
fprintf(stderr,"Outgoing IPv6 packet:\n");
displayIPv6Packet(stderr,(IPv6_fields *)data,size);
#endif

/* Call Link layer */
unsigned short int ether_proto=ETHERNET_PROTO_IPV6;
AssocArray *ether_infos=NULL;
AARRAY_MSETVAR(ether_infos,ifid);
AARRAY_FSETREF(ether_infos,data,data,size);
AARRAY_FSETVAR(ether_infos,dst,ether_target);
AARRAY_FSETVAR(ether_infos,src,intf_eth->ether_addr);
AARRAY_FSETVAR(ether_infos,proto,ether_proto);
if(eventsTrigger(pether->event_out,ether_infos)<0){
  fprintf(stderr,"Cannot trigger Ethernet out event !\n");
  exit(-1);
  }
return 0;
}

//
// Tell if header code is protocol or not
//

static unsigned char ipv6HeaderIsProtocol(int code){
int *p;
for(p=IPv6_header_codes;*p>=0 && *p!=code;p++);
return (*p!=code);
}

//
// Compute network mask
//

IPv6Address ipv6Netmask(int mask){
int i;
IPv6Address addr;
for(i=0;i<IPV6_ADDRESS_SIZE;i++){
  int local=(mask>8)?8:mask; 
  addr.bytes[i]=(1<<local)-1;
  mask=mask-local;
  }
return addr;
}

//
// Compute network address
//

IPv6Address ipv6Network(IPv6Address ip,int mask){
IPv6Address netmask=ipv6Netmask(mask);
IPv6Address result;
int i;
for(i=0;i<IPV6_ADDRESS_SIZE;i++)
  result.bytes[i]=(ip.bytes[i]&netmask.bytes[i]);
return result;
}

//
// Compute broadcast address
//

IPv6Address ipv6Broadcast(IPv6Address ip,int mask){
IPv6Address network=ipv6Network(ip,mask);
IPv6Address netmask=ipv6Netmask(mask);
IPv6Address result;
int i;
for(i=0;i<IPV6_ADDRESS_SIZE;i++)
  result.bytes[i]=(network.bytes[i]|~netmask.bytes[i]);
return result;
}

//
// Compare IPv6 addresses
//

unsigned char ipv6Compare(IPv6Address ip1,IPv6Address ip2){
unsigned char result=1;
int i;
for(i=0;i<IPV6_ADDRESS_SIZE;i++)
  if(ip1.bytes[i]!=ip2.bytes[i]){ result=0; break; }
return result;
}

//
// Convert string to IPv6 address
//

IPv6Address ipv6String2Address(char *string){
IPv6Address address;
int i,count=0;
for(i=0;i<strlen(string);i++) if(string[i]==':') count++;
if(count>7 || count<2) return IPV6_ADDRESS_NULL;
count=7-count;
for(i=0;i<IPV6_ADDRESS_SIZE;i += 2){
  unsigned short int part;
  if(sscanf(string,"%hx",&part)!=1){
    if(count<=0) break;
    for(;count>=0;count--){ 
      address.bytes[i]=0;
      address.bytes[i+1]=0;
      if(count>0) i += 2;
      }
    }
  else{
    address.bytes[i]=(part&0xff00)>>8;
    address.bytes[i+1]=part&0x00ff;
    }
  string=strchr(string,':');
  if(string==NULL){ i += 2; break; }
  string++;
  }
if(i<IPV6_ADDRESS_SIZE) return IPV6_ADDRESS_NULL;
return address;
}

//
// Convert IPv6 address to string
//

char *ipv6Address2String(IPv6Address ip){
static char string[IPV6_STRING_MAX];
string[0]='\0';
int i;
for(i=0;i<IPV6_ADDRESS_SIZE;i += 2){
  char part[IPV6_STRING_MAX];
  sprintf(part,"%x",ip.bytes[i]<<8|ip.bytes[i+1]);
  strcat(string,part);
  if(i<IPV6_ADDRESS_SIZE-2) strcat(string,":");
  }
return string;
}

//
// Convert array to IPv6 address
//

IPv6Address ipv6Array2Address(unsigned char *array){
IPv6Address address;
int i;
for(i=0;i<IPV6_ADDRESS_SIZE;i++) address.bytes[i]=array[i];
return address;
}

//
// Convert IPv6 address to packet field
//

void ipv6Address2Array(IPv6Address ip,unsigned char *field){
int i;
for(i=0;i<IPV6_ADDRESS_SIZE;i++) field[i]=ip.bytes[i];
}

//
// Compute checksum with pseudo header
//

unsigned short int ipv6PseudoHeaderChecksum(
  IPv6Address source,IPv6Address target,int size,int next){
int size_phdr=sizeof(IPv6_pseudo_header);
IPv6_pseudo_header pheader;
bzero(&pheader,size_phdr);
pheader.source=source;
pheader.target=target;
pheader.length=htonl((long)size);
pheader.next=htonl((long)next);
unsigned short int checksum=genericChecksum((unsigned char *)&pheader,size_phdr,0);
return ~checksum;
}
