/*
 * Code for management of network interfaces
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "stack.h"

////
// Constants
////

#define ETHERNET_STRING_MAX		18
#define ETHERNET_PACKET_MAX		1514

////
// Global variables
////

EthernetAddress ETHERNET_ADDRESS_NULL={{0x00,0x00,0x00,0x00,0x00,0x00}};
EthernetAddress ETHERNET_ADDRESS_BROADCAST={{0xFF,0x0FF,0xFF,0xFF,0xFF,0xFF}};
EthernetAddress ETHERNET_ADDRESS_BROADCASTV6={{0x33,0x33,0x00,0x00,0x00,0x00}};

////
// Functions
////

//
// Initialize Ethernet layer
//

unsigned char ethernetInitialize(AssocArray *infos){
if(arraysTestIndex(infos,"intf",0)<0){ arraysFreeArray(infos); return 0; }
AARRAY_MGETVAR(infos,intf,GenericInterface *);
arraysFreeArray(infos);
// Check that interface type is Ethernet
if(intf->type!=INTERFACE_TYPE_ETHERNET) return 0;
EthernetInterface *ether_intf=(EthernetInterface *)intf;
// Create multicast Ethernet addresses
if(ether_intf->ether_multicast==NULL){
  ether_intf->ether_multicast=(EthernetMulticastAddresses *)
    calloc(1,sizeof(EthernetMulticastAddresses));
  if(ether_intf->ether_multicast==NULL)
    { perror("ethernetInitialize.calloc(multicast)"); return 0; }
  if(!stackAddEthernetMulticast(ether_intf->ether_multicast,ETHERNET_ADDRESS_BROADCAST)){
   fprintf(stderr,"Cannot add broadcast Ethernet address to multicast list!\n");
   return 0;
   }
  }
return 1;
}

//
// Decode Ethernet packet
//

#ifdef VERBOSE
#define MAX_BYTES_BY_ROW 16
void displayEthernetPacket(FILE *output,Ethernet_fields *ethernet,int data_size){
fprintf(output,"Target: %s\n",ethernetAddress2String(ethernet->target));
fprintf(output,"Sender: %s\n",ethernetAddress2String(ethernet->sender));
fprintf(output,"Protocol: %04x\n",ntohs(ethernet->protocol));
fprintf(output,"Data:\n  ");
int i;
for(i=0;i<data_size;i++){
  fprintf(output,"%02x ",ethernet->data[i]);
  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
    fprintf(output,"\n");
    if(i<data_size-1) fprintf(output,"  ");
    }
  }
if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
}
#endif

unsigned char ethernetDecodePacket(EventsEvent *event,EventsSelector *selector)
{
    EthernetInterface *intf=(EthernetInterface *)selector->data_this;
    // Some sanity checks
    unsigned char *packet=(unsigned char *)malloc(ETHERNET_PACKET_MAX);
    if(packet==NULL){ perror("ethernetDecodePacket.malloc(packet)"); return 1; }
    int size=read(intf->descriptor,packet,ETHERNET_PACKET_MAX);
    if(size<=0){ free(packet); return 1; }
    packet=(unsigned char *)_realloc(packet,size);
    if(packet==NULL && size>0){ perror("ethernetDecodePacket.realloc"); return 0; }
    int data_size=size-sizeof(Ethernet_fields)+1;
    // Destination verification
    Ethernet_fields *fields=(Ethernet_fields *)packet;
    EthernetAddress target=fields->target;
    if(!stackFindEthernetMulticast(intf->ether_multicast,target) &&
            !ethernetCompare(target,intf->ether_addr))
    { free(packet); return 0; }
#ifdef VERBOSE
    fprintf(stderr,"Incoming Ethernet packet (intf=%s)\n",intf->name_int);
    displayEthernetPacket(stderr,fields,data_size);
#endif
    // Propagate to upper levels
    int proto=ntohs(fields->protocol);
    StackLayers *layer=stackFindLayerByProtocol(LEVEL_NETWORK,proto);
    if(layer==NULL) layer=stackFindLayerByProtocol(LEVEL_ARESOL_IPV4,proto);
    if(layer!=NULL && layer->event_in>=0){
        unsigned char *data=packet;
        memmove(packet,fields->data,data_size);
        data=(unsigned char *)_realloc(data,data_size);
        if(data==NULL && data_size>0)
        { perror("ethernetDecodePacket.realloc"); return 0; }
        AssocArray *infos=NULL;
        AARRAY_FSETVAR(infos,ifid,intf->identity);
        AARRAY_MSETREF(infos,data);
        if(eventsTrigger(layer->event_in,infos)<0){
            fprintf(stderr,"Cannot trigger level 3 protocol event !\n");
            exit(-1);
        }
    }
    else free(packet);
    return 0;
}

//
// Send Ethernet packet
//

unsigned char ethernetSendPacket(EventsEvent *event,EventsSelector *selector)
{
    AssocArray *infos=(AssocArray *)selector->data_this;
    if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"proto",0)<0 ||
       arraysTestIndex(infos,"dst",0)<0 || arraysTestIndex(infos,"src",0)<0)
        { arraysFreeArray(infos); return 1; }
    AARRAY_MGETREF(infos,data,unsigned char *);
    AARRAY_MGETVAR(infos,dst,EthernetAddress);
    AARRAY_MGETVAR(infos,src,EthernetAddress);
    AARRAY_MGETVAR(infos,proto,short int);
    arraysFreeArray(infos);
    EthernetInterface *intf=stackFindEthernetDeviceByAddr(src);
    if(intf==NULL){ free(data); return 0; }
    int offset=sizeof(Ethernet_fields)-1;
    int size=offset+data_size;
    data=(unsigned char *)_realloc(data,size);
    if(data==NULL && size>0){ perror("ethernetSendPacket.realloc"); return 1; }
    memmove(data+offset,data,data_size);
    Ethernet_fields *fields=(Ethernet_fields *)data;
    fields->target=dst;
    fields->sender=src;
    fields->protocol=htons(proto);
#ifdef VERBOSE
    fprintf(stderr,"Outgoing Ethernet packet (intf=%s)\n",intf->name_int);
    displayEthernetPacket(stderr,fields,data_size);
#endif
    int sent=write(intf->descriptor,data,size);
    free(data);
    if(sent==size) return 0; else return 1;
}

//
// Convert string to Ethernet address
//

EthernetAddress ethernetString2Address(char *string){
EthernetAddress address;
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++){
  if(sscanf(string,"%hhx",address.bytes+i)!=1) break;
  string=strchr(string,':');
  if(string==NULL) break;
  string++;
  }
if(i<ETHERNET_ADDRESS_SIZE-1) return ETHERNET_ADDRESS_NULL;
return address;
}

//
// Convert Ethernet address to string
//

char *ethernetAddress2String(EthernetAddress ethernet){
static char string[ETHERNET_STRING_MAX];
string[0]='\0';
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++){
  char byte[ETHERNET_STRING_MAX];
  sprintf(byte,"%02hhx",ethernet.bytes[i]);
  strcat(string,byte);
  if(i<ETHERNET_ADDRESS_SIZE-1) strcat(string,":");
  }
return string;
}

//
// Convert array to Ethernet address
//

EthernetAddress ethernetArray2Address(unsigned char *array){
EthernetAddress address;
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++) address.bytes[i]=array[i];
return address;
}

//
// Convert Ethernet address to array
//

void ethernetAddress2Array(EthernetAddress ethernet,unsigned char *field){
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++) field[i]=ethernet.bytes[i];
}

//
// Compare two Ethernet addresses
//

unsigned char ethernetCompare(EthernetAddress a1,EthernetAddress a2){
unsigned char result=1;
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++)
  if(a1.bytes[i]!=a2.bytes[i]){ result=0; break; }
return result;
}

//
// Test Ethernet addresses
//

unsigned char ethernetBroadcast(EthernetAddress address){
unsigned char result=1;
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++)
  if(address.bytes[i]!=0xff){ result=0; break; }
return result;
}

unsigned char ethernetMulticast(EthernetAddress address){
return address.bytes[0] & 0x01;
}

unsigned char ethernetUnicast(EthernetAddress address){
return !ethernetMulticast(address);
}
