/*
 * Code for routing
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
#include "netroute.h"

////
// Constants
////

////
// Global variables
////

////
// Prototypes
////

////
// Routing functions
////

//
// Apply route algorithm
//

AssocArray *routeDoRouting(
  StackLayers *layer,unsigned char *address,AssocArray *infos){
GenericInterface *intf=NULL;
AssocArray *result=NULL;

// Get outgoing network interface
if(arraysTestIndex(infos,"lsrc",0)<0){
  switch(layer->protocol){
    case ETHERNET_PROTO_IP:{
      EthernetInterface *ethif=
        stackFindEthernetDeviceByIPv4Network(*(IPv4Address *)address);
      intf=(GenericInterface *)ethif;
      }
      break;
    case ETHERNET_PROTO_IPV6:{
      EthernetInterface *ethif=
        stackFindEthernetDeviceByIPv6Network(*(IPv6Address *)address);
      intf=(GenericInterface *)ethif;
      }
      break;
    }
  }
else{
  AARRAY_MGETREF(infos,lsrc,unsigned char *);
  switch(layer->protocol){
    case ETHERNET_PROTO_IP:{
      EthernetInterface *ethif=
        stackFindEthernetDeviceByIPv4(*(IPv4Address *)lsrc);
      intf=(GenericInterface *)ethif;
      }
      break;
    case ETHERNET_PROTO_IPV6:{
      EthernetInterface *ethif=
        stackFindEthernetDeviceByIPv6(*(IPv6Address *)lsrc);
      intf=(GenericInterface *)ethif;
      }
      break;
    }
  AARRAY_MSETREF(result,lsrc);
  }
if(intf==NULL && arraysTestIndex(infos,"ifin",0)>=0){
  AARRAY_MGETVAR(infos,ifin,int);
  intf=stackFindDeviceByIdentity(ifin);
  }
arraysFreeArray(infos);

// Fill result array
if(arraysTestIndex(result,"lsrc",0)<0 &&
   intf!=NULL && intf->type==INTERFACE_TYPE_ETHERNET){
  EthernetInterface *ethif=(EthernetInterface *)intf;
  int size=-1;
  unsigned char *address=NULL;
  switch(layer->protocol){
    case ETHERNET_PROTO_IP:
      size=IPV4_ADDRESS_SIZE;
      address=(unsigned char *)&(ethif->IPv4[0].address);
      break;
    case ETHERNET_PROTO_IPV6:
      size=IPV6_ADDRESS_SIZE;
      address=(unsigned char *)&(ethif->IPv6[0].address);
      break;
    }
  if(size>0 && address!=NULL){
    unsigned char *copy_address=malloc(size);
    if(copy_address==NULL)
      { perror("routeDoRouting.malloc"); return NULL; }
    memcpy(copy_address,address,size);
    AARRAY_FSETREF(result,lsrc,copy_address,size);
    }
  }
AARRAY_FSETVAR(result,iout,intf->identity);
return result;
}
