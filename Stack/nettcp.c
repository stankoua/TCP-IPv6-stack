/*
 * Code for TCP protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netipv6.h"
#include "stack.h"
#include "nettcp.h"

////
// Constants
////

#define EVENTS_PRIORITY_ACK	0

////
// Global variables
////

static TCP_connections *connections=NULL;
static uint32_t sequence;

static int event_ack_schedule=-1;

#ifdef VERBOSE
static char *state_labels[]={
  "close","listen","SYN received","SYN sent",
  "established","close wait","last ack",
  "fin wait 1","fin wait 2","closing",
  "time wait" 
  };
#endif

////
// Prototypes
////

static uint32_t tcpIncrementSequence(uint32_t seq,int inc);
static int tcpCompareSequence(uint32_t seq1,uint32_t seq2);
static uint32_t tcpUpdateSequence(void);
static TCP_connection *tcpAddConnection(SocketAddress local,SocketAddress pair);
static unsigned char tcpDelConnection(TCP_connection *connection);
static TCP_connection *tcpSearchConnection( 
  SocketAddress local,SocketAddress pair);
#ifdef VERBOSE
static void tcpDisplayConnection(FILE *output,TCP_connection *c);
static void tcpDisplayConnections(FILE *output);
#endif
static unsigned char tcpHandlePacket(
  IPv4_fields *iph,TCP_fields *tcp,int size,TCP_connection *connection);
static void tcpAddOptions(TCP_fields **tcp,AssocArray *options);
static void tcpSendDirectVoidAnswer(
  IPv4Address ip_target,unsigned char flag,TCP_fields *tcp,int size);
static void tcpSendData(
  TCP_connection *connection,unsigned char *data,int size,unsigned char flag);
static unsigned char tcpEventScheduleAck(
  EventsEvent *event,EventsSelector *selector);

////
// Functions
////

#ifdef VERBOSE
//
// Display TCP packet
//

#define	MAX_BYTES_BY_ROW	16
void displayTCPPacket(FILE *output,TCP_fields *tcp,int size){
int hlength=4*TCP_get_offset(tcp);
unsigned char *options=tcp->options;
unsigned char *start=(unsigned char *)tcp;
unsigned char *data=start+hlength;
unsigned short int psource=ntohs(tcp->source);
unsigned short int ptarget=ntohs(tcp->target);
fprintf(output,"TCP port source: %04x (%05dd)\n",psource,psource);
fprintf(output,"TCP port target: %04x (%05dd)\n",ptarget,ptarget);
fprintf(output,"TCP sequence: %08x\n",ntohl(tcp->sequence));
int flags=TCP_get_flags(tcp);
if((flags&TCP_FLAGS_ACK)!=0)
  fprintf(output,"TCP acknowledgement: %08x\n",ntohl(tcp->ack));
fprintf(output,"TCP data offset: %d bytes\n",hlength);
fprintf(output,"TCP flags: %02x [ ",flags);
if((flags&TCP_FLAGS_URG)!=0) fprintf(output,"URG ");
if((flags&TCP_FLAGS_ACK)!=0) fprintf(output,"ACK ");
if((flags&TCP_FLAGS_PSH)!=0) fprintf(output,"PSH ");
if((flags&TCP_FLAGS_RST)!=0) fprintf(output,"RST ");
if((flags&TCP_FLAGS_SYN)!=0) fprintf(output,"SYN ");
if((flags&TCP_FLAGS_FIN)!=0) fprintf(output,"FIN ");
fprintf(output,"]\n");
fprintf(output,"TCP window: %04x\n",ntohs(tcp->window));
fprintf(output,"TCP urgent: %04x\n",ntohs(tcp->urgent));
fprintf(output,"TCP checksum: %04x\n",ntohs(tcp->checksum));
for(start=options;start<data;){
  TCP_option_fields *option=(TCP_option_fields *)start;
  if(option->code<2){
    fprintf(output,"TCP Option #%d\n",option->code);
    start++;
    }
  else{
    fprintf(output,"TCP Option #%d (length=%d)\n",
                    option->code,option->length);
    if(option->length>2) fprintf(output,"  ");
    int i;
    for(i=0;i<option->length-2;i++){
      fprintf(output,"%02x ",option->data[i]);
      if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
        fprintf(output,"\n");
        if(i<option->length-1) fprintf(output,"  ");
        }
      }
    if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
    start += option->length;
    }
  }
fprintf(output,"TCP Data:\n");
int i;
int data_size=size-hlength;
if(data_size>0) fprintf(output,"  ");
for(i=0;i<data_size;i++){
  fprintf(output,"%02hhx ",data[i]);
  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
    fprintf(output,"\n");
    if(i<data_size-1) fprintf(output,"  ");
    }
  }
if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
}
#endif

//
// Send event to a TCP process
//

static void tcpProcessEvent(
  TCP_connection *connection,unsigned char type,unsigned char *data,int size){
StackProcess *process=connection->process;
unsigned short int pdst=htons(connection->addr_local.port);
unsigned short int psrc=htons(connection->addr_pair.port);
AssocArray *infos=NULL;
AARRAY_MSETVAR(infos,type);
AARRAY_FSETVAR(infos,ldst,connection->addr_local.address);
AARRAY_FSETVAR(infos,lsrc,connection->addr_pair.address);
AARRAY_MSETVAR(infos,pdst);
AARRAY_MSETVAR(infos,psrc);
AARRAY_FSETREF(infos,data,data,size);
if(eventsTrigger(process->event,infos)<0){
  fprintf(stderr,"Cannot trigger process event (TCP DATA) !\n");
  exit(-1);
  }
}

//
// Analyze TCP packet
//

static unsigned char tcpHandlePacket(
  IPv4_fields *iph,TCP_fields *tcp,int size,TCP_connection *connection){
int state=connection->state;
int flag=TCP_get_flags(tcp);
unsigned char terminate=0;
unsigned char ack=1;
switch(connection->state){
  case TCP_STATE_LISTEN:
    if(flag!=TCP_FLAGS_SYN){ terminate=1; break; }
    connection->state=TCP_STATE_SYNRCVD;
    connection->seq_pair_ack=connection->seq_pair;
    tcpSendData(connection,NULL,0,TCP_FLAGS_SYN);
    ack=0;
    break;
  case TCP_STATE_SYNRCVD:
    if(flag!=TCP_FLAGS_ACK){ terminate=1; break; }
    tcpProcessEvent(connection,PROCESS_CONNECT,NULL,0);
    connection->state=TCP_STATE_ESTABLISHED;
    ack=0;
    break;
  case TCP_STATE_SYNSENT:
    if(flag!=(TCP_FLAGS_SYN|TCP_FLAGS_ACK)){ terminate=1; break; }
    tcpProcessEvent(connection,PROCESS_CONNECT,NULL,0);
    connection->state=TCP_STATE_ESTABLISHED;
    break;
  case TCP_STATE_ESTABLISHED:
    if((flag&TCP_FLAGS_SYN)!=0){ terminate=1; break; }
    if((flag&TCP_FLAGS_FIN)!=0){
      connection->state=TCP_STATE_CLOSEWAIT;
      tcpProcessEvent(connection,PROCESS_CLOSE,NULL,0);
      }
    else{
      int size_hdr=4*TCP_get_offset(tcp);
      int size_data=size-size_hdr;
      if(size_data>0){
        unsigned char *data=(unsigned char *)tcp;
        tcp=(TCP_fields *)malloc(size_hdr);
        memcpy(tcp,data,size_hdr);
        memmove(data,data+size_hdr,size_data);
        data=(unsigned char *)_realloc(data,size_data);
        if(data==NULL && size_data>0)
          { perror("tcpHandlePacket.realloc"); return 0; }
        tcpProcessEvent(connection,PROCESS_DATA,data,size_data);
        }
      }
    break;
  case TCP_STATE_CLOSEWAIT:
    if(flag!=TCP_FLAGS_ACK){ terminate=1; break; }
    break;
  case TCP_STATE_FINWAIT1:
    if((flag&~(TCP_FLAGS_FIN|TCP_FLAGS_ACK))!=0){ terminate=1; break; }
    if(flag==TCP_FLAGS_FIN) connection->state=TCP_STATE_CLOSING;
    else if(flag==TCP_FLAGS_ACK) connection->state=TCP_STATE_FINWAIT2;
    else terminate=1;
    break;
  case TCP_STATE_LASTACK:
    terminate=1;
    break;
  }
#ifdef VERBOSE
if(state!=connection->state)
  fprintf(stderr,"TCP connection changing state from %s to %s.\n",
                 state_labels[state],state_labels[connection->state]);
#endif

if(terminate){
#ifdef VERBOSE
  fprintf(stderr,"TCP packet with flags %02x ",flag);
  fprintf(stderr,"for connection in state %s.\n",state_labels[state]);
  fprintf(stderr," `--> terminating connection.\n");
#endif
  tcpDelConnection(connection);
  }
else{

  /* Update local sequence number */
  if((flag&TCP_FLAGS_ACK)!=0){
    uint32_t seq_ack=ntohl(tcp->ack);
    int diff=tcpCompareSequence(seq_ack,connection->seq_local_ack);
    if(diff>0) connection->seq_local_ack=seq_ack;
    }

  /* Update pair sequence number */
  int size_data=size-TCP_get_offset(tcp)*4;
  if((flag&(TCP_FLAGS_SYN|TCP_FLAGS_FIN))!=0) size_data++;
  connection->seq_pair=tcpIncrementSequence(connection->seq_pair,size_data);

  /* Schedule ACK */
  if(ack){
    AssocArray *con=NULL;
    AARRAY_FSETVAR(con,ldst,connection->addr_local.address);
    AARRAY_FSETVAR(con,pdst,connection->addr_local.port);
    AARRAY_FSETVAR(con,lsrc,connection->addr_pair.address);
    AARRAY_FSETVAR(con,pdst,connection->addr_pair.port);
    if(event_ack_schedule<0){
      event_ack_schedule=eventsCreate(EVENTS_PRIORITY_ACK,NULL);
      if(event_ack_schedule<0){
        fprintf(stdout,"Cannot create TCP ACK event !\n");
        exit(-1);
        }
      if(eventsAddAction(event_ack_schedule,tcpEventScheduleAck,0)<0){
        fprintf(stdout,"Cannot add action to TCP ACK event !\n");
        exit(-1);
        }
      }
    if(eventsSchedule(event_ack_schedule,TCP_PURE_ACK_DELAY,con)<0){
      fprintf(stdout,"Cannot schedule TCP ACK event !\n");
      exit(-1);
      }
#ifdef VERBOSE
    fprintf(stderr,"TCP ACK for sequence %08x scheduled.\n",
                   connection->seq_pair);
#endif

    }
  }
free(iph);
free(tcp);
return 0;
}

//
// Decode TCP packet
//

unsigned char tcpDecodePacket(EventsEvent *event,EventsSelector *selector){
/* Get values from associative array */
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"iph",0)<0)
  { arraysFreeArray(infos); return 1; }
AARRAY_FGETREF(infos,data,unsigned char *,data,size);
AARRAY_HGETREF(infos,iph,IPv4_fields *,iph);
arraysFreeArray(infos);

/* Check TCP headers */
int sum=pseudoHeaderChecksum(
  iph->source,iph->target,IPV4_PROTOCOL_TCP,&data,size);
if(sum<0){ free(data); free(iph); return 0; }
unsigned short int checksum=(unsigned short int)sum;
TCP_fields *tcp=(TCP_fields *)data;
if(checksum!=0){
#ifdef VERBOSE
  fprintf(stderr,"TCP packet: bad checksum\n");
#endif
  free(data); free(iph); return 0;
  }
int psource=ntohs(tcp->source);
int ptarget=ntohs(tcp->target);
if(psource==0){
#ifdef VERBOSE
  fprintf(stderr,"TCP packet: bad source port\n");
#endif
  free(data); free(iph); return 0;
  }
if(ptarget==0){
#ifdef VERBOSE
  fprintf(stderr,"TCP packet: bad destination port\n");
#endif
  free(data); free(iph); return 0;
  }
#ifdef VERBOSE
fprintf(stderr,"Incoming TCP packet:\n");
displayTCPPacket(stderr,tcp,size);
#endif

/* Check the received packet sequence */
SocketAddress local,pair;
local.address=iph->target; local.port=ntohs(tcp->target);
pair.address=iph->source; pair.port=ntohs(tcp->source);
int flag=TCP_get_flags(tcp);
uint32_t seq=ntohl(tcp->sequence);
TCP_connection *connection=tcpSearchConnection(local,pair);
StackProcess *process=NULL;
if(connection==NULL && flag==TCP_FLAGS_SYN){
  process=stackFindProcess(IPV4_PROTOCOL_TCP,local.address,local.port);
  if(process!=NULL){
    connection=tcpAddConnection(local,pair);
    if(connection!=NULL){
      connection->seq_pair=seq;
      connection->state=TCP_STATE_LISTEN;
      connection->process=process;
      }
    }
  }
if(connection!=NULL){
  int diff=tcpCompareSequence(seq,connection->seq_pair);
  if(diff!=0){
#ifdef VERBOSE
    fprintf(stderr,"Bad sequence number in TCP packet, ignoring it.\n");
    tcpDisplayConnection(stderr,connection);
#endif
    free(iph); free(tcp); return 0;
    }
  }
if(connection==NULL){
  tcpSendDirectVoidAnswer(iph->source,TCP_FLAGS_RST,tcp,size);
#ifdef VERBOSE
  if(flag!=TCP_FLAGS_SYN)
    fprintf(stderr,"Martian TCP packet.\n");
  else{
    if(process==NULL)
      fprintf(stderr,"No listening TCP process.\n");
    else
      fprintf(stderr,"Cannot create TCP connection.\n");
    }
#endif
  free(iph); free(tcp); return 0;
  }
#ifdef VERBOSE
fprintf(stderr,"Corresponding TCP connection.\n");
tcpDisplayConnection(stderr,connection);
#endif

/* Check that the process exists */

/* Handle TCP packet */
return tcpHandlePacket(iph,tcp,size,connection);
}

//
// Insert TCP options in packet
//

static void tcpAddOptions(TCP_fields **tcp,AssocArray *options){
int length=(sizeof(TCP_fields)-1)/4;
arraysFreeArray(options);
TCP_set_offset(*tcp,length);
}

//
// Send TCP packet
//

unsigned char tcpSendPacket(EventsEvent *event,EventsSelector *selector){
/* Verify that values exist in associative array */
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"pdst",0)<0 ||
   arraysTestIndex(infos,"psrc",0)<0 || arraysTestIndex(infos,"data",0)<0 || 
   arraysTestIndex(infos,"flag",0)<0 || arraysTestIndex(infos,"opts",0)<0)
  { arraysFreeArray(infos); return 1; }

/* Search for IP layer */
StackLayers *pip=stackFindLayerByProtocol(LEVEL_NETWORK,ETHERNET_PROTO_IP);
if(pip==NULL || pip->event_out<0){ arraysFreeArray(infos); return 0; }

/* Get values from associative array */
AARRAY_FGETVAR(infos,ldst,IPv4Address,target);
AARRAY_MGETVAR(infos,pdst,unsigned short int);
AARRAY_MGETVAR(infos,psrc,unsigned short int);
AARRAY_FGETREF(infos,data,unsigned char *,data,size_data);
AARRAY_MGETVAR(infos,flag,unsigned char);
AARRAY_HGETREF(infos,opts,AssocArray *,options);

/* Find TCP connection, create it if required by process */
IPv4Address source=IPV4_ADDRESS_NULL;
EthernetInterface *device=stackFindEthernetDeviceByIPv4Network(target);
if(device!=NULL) source=device->IPv4[0].address;
SocketAddress local,pair;
local.address=source; local.port=psrc;
pair.address=target; pair.port=pdst;
TCP_connection *connection=tcpSearchConnection(local,pair);
if(connection==NULL && flag==TCP_FLAGS_SYN){
  StackProcess *process=
    stackFindProcess(IPV4_PROTOCOL_TCP,local.address,local.port);
  if(process!=NULL){
    connection=tcpAddConnection(local,pair);
    if(connection!=NULL){
      connection->state=TCP_STATE_SYNSENT;
      connection->process=process;
      }
    }
  }

/* Check local sequence, abort packet emission if necessary */
unsigned char outsider=(connection==NULL);
if(outsider && (flag&TCP_FLAGS_RST)!=0 && arraysTestIndex(infos,"ack",0)>=0)
  outsider=0;
if(outsider){
#ifdef VERBOSE
  fprintf(stderr,"TCP packet to be sent outside of connection.\n");
  fprintf(stderr," `--> dropping it.\n");
#endif
  arraysFreeArray(infos); arraysFreeArray(options); free(data); return 0;
  }
uint32_t seq;
if(arraysTestIndex(infos,"seq",0)>=0) AARRAY_HGETVAR(infos,seq,uint32_t,seq);
else{
  if(connection==NULL){
#ifdef VERBOSE
    fprintf(stderr,
            "TCP packet cannot be sent outside connection without sequence.\n");
#endif
    arraysFreeArray(infos); arraysFreeArray(options); free(data); return 0;
    }
  seq=connection->seq_local;
  AARRAY_MSETVAR(infos,seq);
  }
if(connection!=NULL){
  int diff=tcpCompareSequence(seq,connection->seq_local_ack);
  if(diff<0){
#ifdef VERBOSE
    fprintf(stderr,"TCP packet with already acknowledged sequence.\n");
    fprintf(stderr," `--> %08x < %08x, dropping.\n",
                   seq,connection->seq_local_ack);
#endif
    arraysFreeArray(infos); arraysFreeArray(options); free(data); return 0;
    }
  }

/* Handle acknowledgment */
uint32_t ack=0;
if(connection==NULL && (flag&TCP_FLAGS_RST)!=0){
  flag |= TCP_FLAGS_ACK;
  AARRAY_HGETVAR(infos,ack,uint32_t,ack);
  }
if(connection!=NULL){
  if(tcpCompareSequence(connection->seq_pair_ack,connection->seq_pair)<0){
    flag |= TCP_FLAGS_ACK;
    ack=connection->seq_pair;
    connection->seq_pair_ack=ack;
    }
  }
#ifdef VERBOSE
if((flag&TCP_FLAGS_ACK)!=0)
  fprintf(stderr,"TCP packet with ACK %08x.\n",ack);
#endif
if((flag&(TCP_FLAGS_FIN|TCP_FLAGS_SYN|TCP_FLAGS_RST|TCP_FLAGS_ACK))==0 &&
   size_data==0){
#ifdef VERBOSE
  fprintf(stderr,"TCP packet without special flag nor data.\n");
  fprintf(stderr," `--> dropping it.\n");
#endif
  arraysFreeArray(infos); arraysFreeArray(options); free(data); return 0;
  }

/* Re-schedule the TCP packet */
if((flag&(TCP_FLAGS_FIN|TCP_FLAGS_SYN|TCP_FLAGS_RST))==0){
  int retry=1;
  if(arraysTestIndex(infos,"try",0)>=0){
    AARRAY_HGETVAR(infos,try,int,retry);
    retry++;
    }
  if(retry<TCP_PACKET_MAXTRANSMIT){
    AssocArray *copy_options=arraysCopyArray(options,1);
    int size_copy_options=arraysGetSize(copy_options);
    AssocArray *copy_infos=arraysCopyArray(infos,1);
    AARRAY_FSETREF(copy_infos,"opts",copy_options,size_copy_options);
    AARRAY_FSETVAR(copy_infos,"try",retry);
    StackLayers *ptcp=stackFindLayerByProtocol(LEVEL_TRANSPORT,IPV4_PROTOCOL_TCP);
    if(eventsSchedule(ptcp->event_out,TCP_PACKET_RETRANSMIT,copy_infos)<0){
      fprintf(stderr,"Cannot trigger TCP out event (retransmit) !\n");
      exit(-1);
      }
    #ifdef VERBOSE
    fprintf(stderr,"TCP packet scheduled to be send again.\n");
    #endif
    }
  }
arraysFreeArray(infos);

/* If finalizing connection, update connection state */
if(connection!=NULL && (flag&TCP_FLAGS_FIN)!=0){
  switch(connection->state){
    case TCP_STATE_ESTABLISHED:
      connection->state=TCP_STATE_FINWAIT1;
      break;
    case TCP_STATE_CLOSEWAIT:
      connection->state=TCP_STATE_LASTACK;
      break;
    }
  }

/* Update sequence */
if(connection!=NULL){
  connection->seq_local=tcpIncrementSequence(connection->seq_local,size_data);
  if((flag&TCP_FLAGS_SYN)!=0 || (flag&TCP_FLAGS_FIN)!=0)
    connection->seq_local=tcpIncrementSequence(connection->seq_local,1);
  }

/* Fill TCP headers */
int size_htcp=sizeof(TCP_fields)-1;
int size_tcp=size_data+size_htcp;
data=(unsigned char *)_realloc(data,size_tcp);
if(data==NULL && size_tcp>0)
  { arraysFreeArray(options); perror("tcpSendPacket.realloc"); return 0; }
memmove(data+size_htcp,data,size_data);
bzero(data,size_htcp);
TCP_fields *tcp=(TCP_fields *)data;
tcp->source=htons(psrc);
tcp->target=htons(pdst);
tcp->sequence=htonl(seq);
tcp->ack=htonl(ack);
tcp->window=htons(TCP_WINDOW_DEFAULT);
TCP_set_flags(tcp,flag);
tcpAddOptions(&tcp,options);
int sum=pseudoHeaderChecksum(
  source,target,IPV4_PROTOCOL_TCP,&data,size_tcp);
if(sum<0){ free(data); return 0; }
unsigned short int checksum=(unsigned short int)sum;
tcp=(TCP_fields *)data;
tcp->checksum=htons(checksum);
#ifdef VERBOSE
fprintf(stderr,"Outgoing TCP packet:\n");
displayTCPPacket(stderr,tcp,size_tcp);
#endif

/* Call IP layer */
unsigned char protocol=IPV4_PROTOCOL_TCP;
AssocArray *ip_options=NULL;
AARRAY_FSETVAR(ip_options,lsrc,source);
int size_options=arraysGetSize(ip_options);
AssocArray *ip_infos=NULL;
AARRAY_FSETVAR(ip_infos,ldst,target);
AARRAY_FSETVAR(ip_infos,proto,protocol);
AARRAY_FSETREF(ip_infos,data,data,size_tcp);
AARRAY_FSETREF(ip_infos,opts,ip_options,size_options);
if(eventsTrigger(pip->event_out,ip_infos)<0){
  fprintf(stderr,"Cannot trigger IP out event !\n");
  exit(-1);
  }
return 0;
}

//
// Send an answer TCP packet with non connection associated
//

static void tcpSendDirectVoidAnswer(
  IPv4Address ip_target,unsigned char flag,TCP_fields *tcp,int size){
StackLayers *ptcp=stackFindLayerByProtocol(LEVEL_TRANSPORT,IPV4_PROTOCOL_TCP);
if(ptcp==NULL || ptcp->event_out<0) return;
uint32_t sequence=tcpUpdateSequence();
uint32_t seq=ntohl(tcp->sequence);
short int source=ntohs(tcp->source);
short int target=ntohs(tcp->target);
int initial_flag=TCP_get_flags(tcp);
int size_data=size-TCP_get_offset(tcp)*4;
if((initial_flag&TCP_FLAGS_SYN)!=0) size_data++;
uint32_t ack=tcpIncrementSequence(seq,size_data);
AssocArray *tcp_options=NULL;
int size_options=arraysGetSize(tcp_options);
AssocArray *tcp_infos=NULL;
int size_new_data=0;
AARRAY_FSETVAR(tcp_infos,ldst,ip_target);
AARRAY_FSETVAR(tcp_infos,pdst,source);
AARRAY_FSETVAR(tcp_infos,psrc,target);
AARRAY_FSETREF(tcp_infos,data,NULL,size_new_data);
AARRAY_FSETVAR(tcp_infos,seq,sequence);
AARRAY_MSETVAR(tcp_infos,ack);
AARRAY_MSETVAR(tcp_infos,flag);
AARRAY_FSETREF(tcp_infos,opts,tcp_options,size_options);
if(eventsTrigger(ptcp->event_out,tcp_infos)<0){
  fprintf(stderr,"Cannot trigger TCP out event !\n");
  exit(-1);
  }
}

//
// High level function to send TCP packet
//

static void tcpSendData(
  TCP_connection *connection,unsigned char *data,int size,unsigned char flag){
StackLayers *ptcp=stackFindLayerByProtocol(LEVEL_TRANSPORT,IPV4_PROTOCOL_TCP);
if(ptcp==NULL || ptcp->event_out<0) return;
AssocArray *tcp_options=NULL;
int size_options=arraysGetSize(tcp_options);
AssocArray *tcp_infos=NULL;
AARRAY_FSETVAR(tcp_infos,ldst,connection->addr_pair.address);
AARRAY_FSETVAR(tcp_infos,psrc,connection->addr_local.port);
AARRAY_FSETVAR(tcp_infos,pdst,connection->addr_pair.port);
AARRAY_FSETREF(tcp_infos,data,data,size);
AARRAY_FSETVAR(tcp_infos,seq,connection->seq_local);
AARRAY_MSETVAR(tcp_infos,flag);
AARRAY_FSETREF(tcp_infos,opts,tcp_options,size_options);
if(eventsTrigger(ptcp->event_out,tcp_infos)<0){
  fprintf(stderr,"Cannot trigger TCP out event !\n");
  exit(-1);
  }
}

//
// Event for sending an acknowledgment
//

static unsigned char tcpEventScheduleAck(
  EventsEvent *event,EventsSelector *selector){
/* Verify that values exist in associative array */
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"lsrc",0)<0 ||
   arraysTestIndex(infos,"pdst",0)<0 || arraysTestIndex(infos,"psrc",0)<0)
  { arraysFreeArray(infos); return 1; }

/* Get values from associative array */
AARRAY_MGETVAR(infos,ldst,IPv4Address);
AARRAY_MGETVAR(infos,lsrc,IPv4Address);
AARRAY_MGETVAR(infos,pdst,unsigned short int);
AARRAY_MGETVAR(infos,psrc,unsigned short int);
arraysFreeArray(infos);

/* Find the TCP connexion */
SocketAddress local,pair;
local.address=lsrc; local.port=psrc;
pair.address=ldst; pair.port=pdst;
TCP_connection *connection=tcpSearchConnection(local,pair);

/* Send the TCP packet */
if(connection!=NULL){
#ifdef VERBOSE
  fprintf(stderr,"Send differed ACK for this connection:\n");
  tcpDisplayConnection(stderr,connection);
#endif
  tcpSendData(connection,NULL,0,0);
  }
return 0;
}

//
// Add offset to sequence number
//

static uint32_t tcpIncrementSequence(uint32_t seq,int inc){
return seq+inc;
}

//
// Compare two sequence numbers 
//

static int tcpCompareSequence(uint32_t seq1,uint32_t seq2){
int diff1,diff2;
int sign=(seq1==seq2)?0:((seq1-seq2>0)?1:-1);
if(sign==0) return sign;
if(sign>0){ diff1=seq2-seq1; diff2=seq1+(0xffffffff-seq2); }
else{ diff1=seq1-seq2; diff2=seq2+(0xffffffff-seq1); }
if(diff2<diff1) sign *= -1;
return sign;
}

//
// Update local start of sequence
//

static uint32_t tcpUpdateSequence(void){
unsigned long int factor=0xfffff/RAND_MAX;
if(factor==0) factor=1;
int offset=(random()*factor)&0xffff;
sequence=tcpIncrementSequence(sequence,offset);
return sequence;
}

#ifdef VERBOSE
//
// Display TCP connections
//

static void tcpDisplayConnection(FILE *output,TCP_connection *c){
fprintf(output,"  state %s\n",state_labels[c->state]);
fprintf(output,"  local address (%s",ipAddress2String(c->addr_local.address));
fprintf(output,",%u)\n",c->addr_local.port);
fprintf(output,"  pair address  (%s",ipAddress2String(c->addr_pair.address));
fprintf(output,",%u)\n",c->addr_pair.port);
fprintf(output,"  local sequence %08x (ACK %08x)\n",
               c->seq_local,c->seq_local_ack);
fprintf(output,"  pair sequence  %08x (ACK %08x)\n",
               c->seq_pair,c->seq_pair_ack);
}

static void tcpDisplayConnections(FILE *output){
int i;
fprintf(output,"=== TCP connections ===\n");
if(connections!=NULL)
  for(i=0;i<connections->size;i++){
    TCP_connection *c=connections->connections+i;
    if(c->state==TCP_STATE_CLOSE) continue;
    tcpDisplayConnection(output,c);
    }
fprintf(output,"=======================\n");
}
#endif

//
// Add TCP connection to the list of active connections
//

static TCP_connection *tcpAddConnection(SocketAddress local,SocketAddress pair){
if(connections==NULL){
  connections=(TCP_connections *)malloc(sizeof(TCP_connections));
  connections->allocated=0;
  connections->size=0;
  connections->connections=NULL;
  unsigned long int factor=0xffffffff/RAND_MAX;
  if(factor==0) factor=1;
  srandom(time(NULL));
  sequence=random()*factor;
  }
if(connections->size>=connections->allocated){
  int newsize=(connections->allocated+1)*sizeof(TCP_connection);
  TCP_connection *newcon=
    (TCP_connection *)_realloc(connections->connections,newsize);
  if(newcon==NULL && newsize>0) return NULL;
  connections->connections=newcon;
  connections->allocated++;
  }
TCP_connection *connection=connections->connections+connections->size;
connection->state=TCP_STATE_CLOSE;
connection->addr_local=local;
connection->addr_pair=pair;
connection->seq_local=tcpUpdateSequence();
connection->seq_local_ack=tcpIncrementSequence(connection->seq_local,-1);
connection->seq_pair=0;
connection->seq_pair_ack=0;
connections->size++;
return connection;
}

//
// Remove TCP connection from the list of active connections
//

static unsigned char tcpDelConnection(TCP_connection *connection){
int i;
if(connections==NULL) return 0;
for(i=0;i<connections->size;i++)
  if(connections->connections+i==connection) break;
if(i>=connections->size) return 1;
connections->connections[i]=connections->connections[connections->size-1];
connections->size--;
return 0;
}

//
// Search a TCP connection in the list of active connections
//

static TCP_connection *tcpSearchConnection(
  SocketAddress local,SocketAddress pair){
int i;
if(connections==NULL) return NULL;
for(i=0;i<connections->size;i++){
  TCP_connection *c=connections->connections+i;
  unsigned char ipl_ok=ipCompare(local.address,IPV4_ADDRESS_NULL) ||
                       ipCompare(local.address,c->addr_local.address);
  unsigned char ipp_ok=ipl_ok && ipCompare(pair.address,c->addr_pair.address);
  unsigned char ptl_ok=ipp_ok && (local.port==c->addr_local.port);
  unsigned char ptp_ok=ptl_ok && (pair.port==c->addr_pair.port);
  if(ptp_ok) return c;
  }
return NULL;
}
