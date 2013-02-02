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
#include "neticmpv6.h"
#include "netudpv6.h"
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
void displayUDPv6Packet(FILE *output,UDPv6_fields *udp,int size)
{
    fprintf(output,"UDPv6 Port source: %04x\n",ntohs(udp->source));
    fprintf(output,"UDPv6 Port target: %04x\n",ntohs(udp->target));
    fprintf(output,"UDPv6 Checksum: %04x\n",ntohs(udp->checksum));
    fprintf(output,"UDPv6 Data:\n  ");
    int i;
    int data_size=size-sizeof(UDPv6_fields)+1;
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

unsigned char udpv6DecodePacket(EventsEvent *event,EventsSelector *selector)
{
    /* Get values from associative array */
    AssocArray *infos=(AssocArray *)selector->data_this;
    if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"iph",0)<0)
    { arraysFreeArray(infos); return 1; }

    AARRAY_FGETREF(infos,data,unsigned char *,data,size);   // int size = size(data), getting the data(udp packet)
    AARRAY_HGETREF(infos,iph,IPv6_fields *,iph);    // getting the ipv6 headers
    AARRAY_MGETVAR(infos,ifid,int);      // will be useful for icmp triggering
    AARRAY_MGETVAR(infos,l3id,int);     // same for him
    AARRAY_FGETVAR(infos,hsum,unsigned short int,csum_headers);
    arraysFreeArray(infos);

    /* Check UDP headers */
    UDPv6_fields *udp=(UDPv6_fields *)data;
    if(ntohs(udp->length)!=size){
#ifdef VERBOSE
        fprintf(stderr,"UDPv6 packet: bad length\n");
#endif
        free(data); free(iph); return 0;
    }

    if(udp->checksum!=0){
        unsigned short int checksum=genericChecksum(data,size,csum_headers);
        //int sum=ipv6PseudoHeaderChecksum(
        //iph->source,iph->target,size,IPV6_PROTOCOL_UDP);
        //if(sum<0){ free(data); free(iph); return 0; }
        //unsigned short int checksum=(unsigned short int)sum;
        if(checksum!=0){
#ifdef VERBOSE
            fprintf(stderr,"UDPv6 packet: bad checksum\n");
#endif
            free(data); free(iph); return 0;
        }
    }
    int psource_net=udp->source;        // sender
    int ptarget_net=udp->target;        // us
    int psource=ntohs(udp->source);
    int ptarget=ntohs(udp->target);
    if(psource==0){
#ifdef VERBOSE
        fprintf(stderr,"UDPv6 packet: bad source port\n");
#endif
        free(data); free(iph); return 0;
    }
    if(ptarget==0){
#ifdef VERBOSE
        fprintf(stderr,"UDPv6 packet: bad destination port\n");
#endif
        free(data); free(iph); return 0;
    }

#ifdef VERBOSE
    fprintf(stderr,"Incoming UDPv6 packet:\n");
    displayUDPv6Packet(stderr,udp,size);
#endif

    /* Process UDP data */
    unsigned char status=0;
    StackProcess *process=
        stackFindProcessIpv6(IPV6_PROTOCOL_UDP,iph->target,ptarget);
    if(process==NULL){
        StackLayers *picmp=stackFindLayerByProtocol(LEVEL_CONTROL_IPV6,IPV6_PROTOCOL_ICMP);
        if(picmp!=NULL && picmp->event_out>=0){
            unsigned char type=ICMPV6_TYPE_UNREACHABLE;
            unsigned char code=ICMPV6_UNREACHABLE_CODE_PORT;
            /*
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
               */
            // Sending icmpv6 packet instead of icmpv4 packet
            int reply_size=iph->length+4;
            data=(unsigned char *)_realloc(data,reply_size);
            if(data==NULL && reply_size>0)
            { perror("ipv6DecodePacket.realloc"); return 0; }
            memmove(data+4,data,reply_size-4);
            bzero(data,4);
            AssocArray *icmp_infos=NULL;
            AARRAY_MSETVAR(icmp_infos,ifid);
            AARRAY_FSETVAR(infos,l3id,l3id);
            AARRAY_MSETVAR(icmp_infos,type);
            AARRAY_MSETVAR(icmp_infos,code);
            AARRAY_FSETREF(icmp_infos,data,data,reply_size);
            AARRAY_FSETREF(icmp_infos,ldst,&iph->source,sizeof(IPv6Address));
            if(eventsTrigger(picmp->event_out,icmp_infos)<0){
                fprintf(stderr,"Cannot trigger ICMPv6 out event !\n");
                exit(-1);
            }
        }
        else free(data);
    }
    else{
        int size_hdr=sizeof(UDPv6_fields)-1;
        int size_data=size-size_hdr;
        memmove(data,data+size_hdr,size_data);
        data=(unsigned char *)_realloc(data,size_data);
        if(data==NULL && size_data>0){ perror("udpv6DecodePacket.realloc"); return 0; }
        unsigned char type=PROCESS_DATA;
        AssocArray *infos=NULL;
        AARRAY_MSETVAR(infos,type);
        AARRAY_FSETVAR(infos,ldst,iph->target);     // us
        AARRAY_FSETVAR(infos,lsrc,iph->source);     // sender
        AARRAY_FSETVAR(infos,pdst,ptarget_net);
        AARRAY_FSETVAR(infos,psrc,psource_net);
        AARRAY_FSETREF(infos,data,data,size_data);
        if(eventsTrigger(process->event,infos)<0){
            fprintf(stderr,"Cannot trigger process event (UDPv6 DATA) !\n");
            exit(-1);
        }
    }
    free(iph);
    return status;
}

//
// Send UDP packet
//

unsigned char udpv6SendPacket(EventsEvent *event,EventsSelector *selector)
{
    /* Get values from associative array */
    AssocArray *infos=(AssocArray *)selector->data_this;
    if(arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"pdst",0)<0 ||
       arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"psrc",0)<0)
        { arraysFreeArray(infos); return 1; }
    StackLayers *pip=stackFindLayerByProtocol(LEVEL_NETWORK,ETHERNET_PROTO_IPV6);
    if(pip==NULL || pip->event_out<0){ arraysFreeArray(infos); return 0; }
    AARRAY_FGETVAR(infos,ldst,IPv6Address,target);
    AARRAY_MGETVAR(infos,pdst,unsigned short int);
    AARRAY_MGETVAR(infos,psrc,unsigned short int);
    AARRAY_FGETREF(infos,data,unsigned char *,data,size_data);
    arraysFreeArray(infos);

    /* Fill UDP headers */
    IPv6Address source=IPV6_ADDRESS_NULL;
    EthernetInterface *device=stackFindEthernetDeviceByIPv6Network(target);
    if(device!=NULL) source=device->IPv6[0].address;
    int size_hudp=sizeof(UDPv6_fields)-1;
    int size_udp=size_data+size_hudp;
    data=(unsigned char *)_realloc(data,size_udp);
    if(data==NULL && size_udp>0){ perror("udpv6SendPacket.realloc"); return 0; }
    memmove(data+size_hudp,data,size_data);
    bzero(data,size_hudp);
    UDPv6_fields *udp=(UDPv6_fields *)data;
    udp->source=htons(psrc);
    udp->target=htons(pdst);
    udp->length=htons(size_udp);
    int sum=ipv6PseudoHeaderChecksum(
            source,target,size_udp,IPV6_PROTOCOL_UDP);
    if(sum<0){ free(data); return 0; }
    unsigned short int checksum=(unsigned short int)sum;
    udp=(UDPv6_fields *)data;
    udp->checksum=htons(checksum);
#ifdef VERBOSE
    fprintf(stderr,"Outgoing UDPv6 packet:\n");
    displayUDPv6Packet(stderr,udp,size_udp);
#endif

    /* Call IP layer */
    unsigned char protocol=IPV6_PROTOCOL_UDP;
    AssocArray *ip_options=NULL;
    AARRAY_FSETVAR(ip_options,lsrc,source);
    int size_options=arraysGetSize(ip_options);
    AssocArray *ip_infos=NULL;
    AARRAY_FSETVAR(ip_infos,ldst,target);
    AARRAY_FSETVAR(ip_infos,proto,protocol);
    AARRAY_FSETREF(ip_infos,data,data,size_udp);
    AARRAY_FSETREF(ip_infos,opts,ip_options,size_options);
    if(eventsTrigger(pip->event_out,ip_infos)<0){
        fprintf(stderr,"Cannot trigger IPv6 out event !\n");
        exit(-1);
    }

    return 0;
}
