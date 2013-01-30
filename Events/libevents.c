/*
 * Common code for handling events
 */

////
// Include files
////
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>

#include "libevents.h"

////
// Macros
////
#define printTabs(output,nb) { int i; for(i=0;i<nb;i++) fprintf(output," "); }

////
// Global variables
////

static EventsStruct *events=NULL;
static int waiting_room[2]={-1,-1};

////
// Private prototypes
////
static EventsStruct *eventsInit(void);
static int eventsExpand(EventsStruct *events);
static int eventsSortEvents(const void *v1,const void *v2);
static EventsEvent *eventsGetEventById(int identity);
static int eventsGetEventFreeId(void);
static void eventsActionsInit(EventsEvent *event);
static int eventsActionsExpand(EventsEvent *event);
static int eventsSortActions(const void *v1,const void *v2);
static void eventsSelectorsInit(EventsEvent *event);
static int eventsSelectorsExpand(EventsEvent *event);
static int eventsGetSelectorFreeId(EventsEvent *event);
static EventsSelector *eventsGetSelectorById(EventsEvent *event,int identity);
static EventsSelector *eventsAddSelector(int identity,int type,
                                         void *data);
static void eventsRemoveSelector(EventsEvent *event,int id_selector,
                                 unsigned removeOnDescriptor);
static void eventsHandle(EventsEvent **event,EventsSelector **selector);
static fd_set eventsBuildSet(int *max,int *nb);
static struct timeval eventsNextTimer(void);
static void eventsUpdateTimers(long int delta);
#ifdef DEBUG_EVENTS
static void eventsDisplayEvent(FILE *output,short int tabs,EventsEvent *event);
static void eventsDisplayAction(FILE *output,short int tabs,
                                EventsAction *action);
static void eventsDisplaySelector(FILE *output,short int tabs,
                                  EventsSelector *selector);
static void eventsDisplayWaitValue(FILE *output,unsigned char size,void *value);
#endif
static void *_realloc(void *ptr, size_t size);

////
// Functions
////

//
// Initialize events structure
//
static EventsStruct *eventsInit(void){
EventsStruct *result=(EventsStruct *)malloc(sizeof(EventsStruct));
if(result==NULL) return NULL;
result->events=(EventsEvent *)malloc(EVENTS_BLOCK_SIZE*sizeof(EventsEvent));
if(result->events==NULL){ perror("eventsInit.malloc"); exit(-1); }
result->events_nb_allocated=EVENTS_BLOCK_SIZE;
result->events_nb=0;
return result;
}

//
// Add space to events structure
//
static int eventsExpand(EventsStruct *events){
events->events_nb_allocated += EVENTS_BLOCK_SIZE;
int size=events->events_nb_allocated*sizeof(EventsEvent);
events->events=(EventsEvent *)_realloc(events->events,size);
return (events->events==NULL)?-1:0;
}

//
// Sort events
//
static int eventsSortEvents(const void *v1,const void *v2){
EventsEvent *e1=(EventsEvent *)v1;
EventsEvent *e2=(EventsEvent *)v2;
return (e1->priority-e2->priority);
}

//
// Get a free identity for an event
//
static int eventsGetEventFreeId(void){
int id=0;
while(1){
  int i;
  unsigned char found=0;
  for(i=0;i<events->events_nb;i++)
    if(events->events[i].identity==id){ id++; found=1; break;}
  if(!found || id<0) break;
  }
if(id<0) return -1; else return id;
}

//
// Get an event by its identity
//
static EventsEvent *eventsGetEventById(int identity){
int i;
for(i=0;i<events->events_nb;i++)
  if(events->events[i].identity==identity) break;
if(i<events->events_nb) return events->events+i;
return NULL;
}

//
// Create an event
//
int eventsCreate(int priority,void *data){
if(events==NULL) events=eventsInit();
if(events==NULL) return -1;
int identity=eventsGetEventFreeId();
if(identity<0) return -1;
if(events->events_nb>=events->events_nb_allocated)
  if(eventsExpand(events)<0) return -1;
EventsEvent *event=events->events+events->events_nb;
event->identity=identity;
event->priority=priority;
event->data_init=data;
event->actions=NULL;
event->actions_nb=0;
event->actions_nb_allocated=0;
event->selectors=NULL;
event->selectors_nb=0;
event->selectors_nb_allocated=0;
events->events_nb++;
#ifdef DEBUG_EVENTS
fprintf(stderr,"New event (total=%d):\n",events->events_nb);
eventsDisplayEvent(stderr,2,event);
#endif
qsort(events->events,events->events_nb,sizeof(EventsEvent),eventsSortEvents);
return events->events_nb-1;
}

//
// Remove an event
//
void eventsRemove(int identity){
EventsEvent *event=eventsGetEventById(identity);
if(event!=NULL){
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Removing event #%d:\n",identity);
#endif
  if(events->events_nb>1)
    *event=events->events[events->events_nb-1];
  if(event->actions!=NULL) free(event->actions);
  if(event->selectors!=NULL) free(event->selectors);
  events->events_nb--;
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Now %d remaining events.\n",events->events_nb);
#endif
  if(events->events_nb==0){
     free(events->events);
     free(events);
     events=NULL;
     }
  }
else{
#ifdef DEBUG_EVENTS
fprintf(stderr,"Cannot remove event of id #%d!\n",identity);
#endif
 }
}

//
// Display an event
//
#ifdef DEBUG_EVENTS
static void eventsDisplayEvent(FILE *output,short int tabs,EventsEvent *event){
int i;
printTabs(output,tabs);
fprintf(output,"id: %d, priority: %d, data: %x\n",
        event->identity,event->priority,(unsigned int)event->data_init);
fprintf(output,"selectors: %d/%d\n",
        event->selectors_nb,event->selectors_nb_allocated);
for(i=0;i<event->selectors_nb;i++){
  printTabs(output,tabs); fprintf(output,"selector #%d\n",i);
  eventsDisplaySelector(output,tabs+2,event->selectors+i);
  }
fprintf(output,"actions: %d/%d\n",
        event->actions_nb,event->actions_nb_allocated);
for(i=0;i<event->actions_nb;i++){
  printTabs(output,tabs); fprintf(output,"action #%d\n",i);
  eventsDisplayAction(output,tabs+2,event->actions+i);
  }
}
#endif

//
// Initialize selectors structure
//
static void eventsSelectorsInit(EventsEvent *event){
event->selectors=(EventsSelector *)
  malloc(EVENTS_SELECTORS_BLOCK_SIZE*sizeof(EventsSelector));
if(event->selectors==NULL){ perror("eventsSelectorsInit.malloc"); exit(-1); }
event->selectors_nb_allocated=EVENTS_SELECTORS_BLOCK_SIZE;
event->selectors_nb=0;
}

//
// Add space to selectors structure
//
static int eventsSelectorsExpand(EventsEvent *event){
event->selectors_nb_allocated += EVENTS_SELECTORS_BLOCK_SIZE;
int size=event->selectors_nb_allocated*sizeof(EventsSelector);
event->selectors=(EventsSelector *)_realloc(event->selectors,size);
return (event->selectors==NULL)?-1:0;
}

//
// Get a free identity for a selector
//
static int eventsGetSelectorFreeId(EventsEvent *event){
int id=0;
while(1){
  int i;
  unsigned char found=0;
  for(i=0;i<event->selectors_nb;i++)
    if(event->selectors[i].identity==id){ id++; found=1; break;}
  if(!found || id<0) break;
  }
if(id<0) return -1; else return id;
}

//
// Get a free identity for a selector
//
static EventsSelector *eventsGetSelectorById(EventsEvent *event,int identity){
int i;
for(i=0;i<event->selectors_nb;i++)
  if(event->selectors[i].identity==identity)
    return event->selectors+i;
return NULL;
}

//
// Add selector to an event
//
static EventsSelector *eventsAddSelector(int identity,int type,
                                         void *data){
EventsEvent *event=eventsGetEventById(identity);
int id_selector=eventsGetSelectorFreeId(event);
if(identity<0) return NULL;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding selector to event of identity %d.\n",identity);
#endif
if(event->selectors==NULL) eventsSelectorsInit(event);
if(event->selectors_nb>=event->selectors_nb_allocated)
  if(eventsSelectorsExpand(event)<0) return NULL;
EventsSelector *selector=event->selectors+event->selectors_nb;
selector->identity=id_selector;
selector->type=type;
selector->data_this=data;
event->selectors_nb++;
return selector;
}

//
// Remove selector from an event
//
static void eventsRemoveSelector(EventsEvent *event,int id_selector,
                                 unsigned removeOnDescriptor){
EventsSelector *selector=eventsGetSelectorById(event,id_selector);
if(selector==NULL){
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Trying to remove inexistant selector!\n");
#endif
  return;
  }
if(selector->type==EVENTS_ONDESCRIPTOR && removeOnDescriptor==0) return;
int i=selector-event->selectors;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Removing selector #%d (id=%d) from event of id %d.\n",
                i,id_selector,event->identity);
#endif
if(selector->type==EVENTS_ONWAKE)
  free(selector->selector.wait_point.value);
if(event->selectors_nb>1)
  event->selectors[i]=event->selectors[event->selectors_nb-1];
event->selectors_nb--;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after removal:\n");
eventsDisplayEvent(stderr,2,event);
#endif
}

//
// Display a selector
//
#ifdef DEBUG_EVENTS
static void eventsDisplaySelector(FILE *output,short int tabs,EventsSelector *selector){
printTabs(output,tabs);
fprintf(output,"id: %d\n",selector->identity);
printTabs(output,tabs);
fprintf(output,"type: ");
switch(selector->type){
  case EVENTS_ONDESCRIPTOR:
    fprintf(output,"descriptor (fd=%d)",selector->selector.descriptor);
    break;
  case EVENTS_ONTRIGGER:
    fprintf(output,"trigger");
    break;
  case EVENTS_ONTIMER:
    fprintf(output,"timer (timeout=%ld)",selector->selector.timeout);
    break;
  case EVENTS_ONWAKE:{
    fprintf(output,"wait wake (value=");
    unsigned char size=selector->selector.wait_point.size;
    void *value=selector->selector.wait_point.value;
    eventsDisplayWaitValue(output,size,value);
    fprintf(output,")");
    }
    break;
  }
fprintf(output,"\n");
printTabs(output,tabs);
fprintf(output,"data: %x\n",(unsigned int)selector->data_this);
}
#endif

//
// Associate a file descriptor to an event
// (should be handled when activity detected)
//
int eventsAssociateDescriptor(int identity,int descriptor,void *data){
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding descriptor selector (descriptor=%d).\n",descriptor);
#endif
EventsSelector *selector=eventsAddSelector(identity,EVENTS_ONDESCRIPTOR,data);
if(selector==NULL) return -1;
selector->selector.descriptor=descriptor;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after selector insertion:\n");
eventsDisplayEvent(stderr,2,eventsGetEventById(identity));
#endif
return 0;
}

//
// Trigger an event (should be handled as soon as possible)
//
int eventsTrigger(int identity,void *data){
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding trigger selector.\n");
#endif
EventsSelector *selector=eventsAddSelector(identity,EVENTS_ONTRIGGER,data);
if(selector==NULL) return -1;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after selector insertion:\n");
eventsDisplayEvent(stderr,2,eventsGetEventById(identity));
#endif
return 0;
}

//
// Schedule event (should be handled when timeout expires)
//
int eventsSchedule(int identity,long timeout,void *data){
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding timeout selector (timeout=%ld).\n",timeout);
#endif
EventsSelector *selector=eventsAddSelector(identity,EVENTS_ONTIMER,data);
if(selector==NULL) return -1;
selector->selector.timeout=timeout;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after selector insertion:\n");
eventsDisplayEvent(stderr,2,eventsGetEventById(identity));
#endif
return 0;
}

//
// Set a wait point, event will be fired by the eventsWake function
//
int eventsWaitPoint(int identity,void *value,unsigned char size,void *data){
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding wait point selector (value=");
eventsDisplayWaitValue(stderr,size,value);
fprintf(stderr,").\n");
#endif
EventsSelector *selector=eventsAddSelector(identity,EVENTS_ONWAKE,data);
if(selector==NULL) return -1;
selector->selector.wait_point.size=size;
selector->selector.wait_point.value=malloc(size);
if(selector->selector.wait_point.value==NULL)
  { perror("eventsWaitPoint.malloc"); exit(-1); }
memcpy(selector->selector.wait_point.value,value,size);
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after selector insertion:\n");
eventsDisplayEvent(stderr,2,eventsGetEventById(identity));
#endif
return 0;
}

//
// Wake the event with corresponding wait point
//
int eventsWake(void *value,unsigned char size){
if(write(waiting_room[1],&size,sizeof(size))!=sizeof(size)) return -1;
if(write(waiting_room[1],value,size)!=size) return -1;
return 0;
}

//
// Initialize actions structure
//
static void eventsActionsInit(EventsEvent *event){
event->actions=(EventsAction *)malloc(EVENTS_ACTIONS_BLOCK_SIZE*sizeof(EventsAction));
if(event->actions==NULL) { perror("eventsActionsInit.malloc"); exit(-1); }
event->actions_nb_allocated=EVENTS_ACTIONS_BLOCK_SIZE;
event->actions_nb=0;
}

//
// Add space to events structure
//
static int eventsActionsExpand(EventsEvent *event){
event->actions_nb_allocated += EVENTS_ACTIONS_BLOCK_SIZE;
int size=event->actions_nb_allocated*sizeof(EventsAction);
event->actions=(EventsAction *)_realloc(event->actions,size);
return (event->actions==NULL)?-1:0;
}

//
// Sort actions
//
static int eventsSortActions(const void *v1,const void *v2){
EventsAction *a1=(EventsAction *)v1;
EventsAction *a2=(EventsAction *)v2;
return (a1->level-a2->level);
}

//
// Add action function to an event
//
int eventsAddAction(int identity,
                    unsigned char (*handler)(EventsEvent *,EventsSelector *),
                    int level){
EventsEvent *event=eventsGetEventById(identity);
if(event==NULL) return -1;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding action to event of id %d.\n",identity);
#endif
if(event->actions==NULL) eventsActionsInit(event);
if(event->actions_nb>=event->actions_nb_allocated)
  if(eventsActionsExpand(event)<0) return -1;
EventsAction *action=event->actions+event->actions_nb;
action->level=level;
action->action=handler;
event->actions_nb++;
qsort(event->actions,event->actions_nb,sizeof(EventsAction),eventsSortActions);
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after action insertion:\n");
eventsDisplayEvent(stderr,2,event);
#endif
return 0;
}

//
// Display action
//
#ifdef DEBUG_EVENTS
static void eventsDisplayAction(FILE *output,short int tabs,
                                EventsAction *action){
printTabs(output,tabs);
fprintf(output,"level: %d, action: %x\n",action->level,
               (unsigned int)action->action);
}
#endif

//
// Build a set of descriptors from events list
//
static fd_set eventsBuildSet(int *max,int *nb){
int i,j;
fd_set set;
unsigned char wait_point=0;
FD_ZERO(&set);
if(max!=NULL) *max=-1;
if(nb!=NULL) *nb=0;
for(i=0;i<events->events_nb;i++){
  EventsEvent *event=events->events+i;
  for(j=0;j<event->selectors_nb;j++){
    EventsSelector *selector=event->selectors+j;
    if(selector->type==EVENTS_ONDESCRIPTOR ||
       selector->type==EVENTS_ONWAKE){
      int fd;
      if(selector->type==EVENTS_ONWAKE) fd=waiting_room[0];
      else fd=selector->selector.descriptor;
      FD_SET(fd,&set);
      if(max!=NULL && (*max)<fd) *max=fd;
      if(nb!=NULL){
        if(selector->type==EVENTS_ONWAKE)
          { if(wait_point==0){ wait_point=1; (*nb)++; } }
        else (*nb)++;
        }
      }
    }
  }
return set; 
}

//
// Find the next timer to expire
//
static struct timeval eventsNextTimer(void){
int i,j;
struct timeval timer;
timer.tv_sec=-1;
for(i=0;i<events->events_nb;i++){
  EventsEvent *event=events->events+i;
  for(j=0;j<event->selectors_nb;j++){
    EventsSelector *selector=event->selectors+j;
    if(selector->type==EVENTS_ONTIMER){
      long int delta=selector->selector.timeout;
      long int sec=delta/1000000;
      long int usec=delta%1000000;
      if(timer.tv_sec<0 ||
         (timer.tv_sec>sec || (timer.tv_sec==sec && timer.tv_usec>usec)))
        { timer.tv_sec=sec; timer.tv_usec=usec; }
      }
    if(selector->type==EVENTS_ONTRIGGER){
      timer.tv_sec=0;
      timer.tv_usec=0;
      }
    }
  }
return timer; 
}

//
// Update timers
//
static void eventsUpdateTimers(long int delta){
int i,j;
for(i=0;i<events->events_nb;i++){
  EventsEvent *event=events->events+i;
  for(j=0;j<event->selectors_nb;j++){
    EventsSelector *selector=event->selectors+j;
    if(selector->type==EVENTS_ONTIMER){
      long int timeout=selector->selector.timeout;
      long int new=timeout-delta;
      if(new<0) new=0;
      selector->selector.timeout=new;
      }
    }
  }
}

//
// Handle events
//
static void eventsHandle(EventsEvent **event,EventsSelector **selector){
int i;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Calling action(s) for event of id %d\n",(*event)->identity);
#endif
int id_event=(*event)->identity;
int id_selector=(*selector)->identity;
unsigned char status=0;
for(i=0;i<(*event)->actions_nb;i++){
  EventsAction *action=(*event)->actions+i;
#ifdef DEBUG_EVENTS
  fprintf(stderr,"  calling action #%d:\n",i);
  eventsDisplayAction(stderr,4,action);
#endif
  unsigned char result=action->action(*event,*selector);
  *event=eventsGetEventById(id_event);
  if(*event==NULL){
#ifdef DEBUG_EVENTS
    fprintf(stderr,"Mysterious disparition of event with id %d\n",id_event);
#endif
    return;
    }
  *selector=eventsGetSelectorById(*event,id_selector);
  if(*selector==NULL){
#ifdef DEBUG_EVENTS
    fprintf(stderr,"Mysterious disparition of selector with id=(%d/%d)\n",
            id_event,id_selector);
#endif
    return;
    }
  if(result!=0){ status=1; break; }
  }
eventsRemoveSelector(*event,id_selector,status);
}

void eventsScan(void){
int i,j;
// Create pipe for wait points
if(pipe(waiting_room)<0){ perror("eventsScan.pipe"); exit(-1); }

// Loop until there is no more event
while(1){
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Scanning %d event(s).\n",events->events_nb);
#endif
  if(events->events_nb<=0) break;

  // Wait for events
  int max,nb;
  fd_set set=eventsBuildSet(&max,&nb);
  struct timeval timer=eventsNextTimer();
  struct timeval save=timer;
  struct timeval *param;
  if(nb==0 && timer.tv_sec<0) return;
  if(timer.tv_sec<0) param=NULL; else param=&timer;
#ifdef DEBUG_EVENTS
  if(param==NULL)
    fprintf(stderr,"Waiting indefinitely,");
  else
    fprintf(stderr,"Waiting %d sec and %d usec,",
                   (int)param->tv_sec,(int)param->tv_usec); 
  fprintf(stderr," on %d descriptor(s).\n",nb); 
#endif
  int status=select(max+1,&set,NULL,NULL,param);
  if(status<0){ perror("eventsScan.select"); exit(-1); }
  long int delta=1000000*(save.tv_sec-timer.tv_sec)+
                 save.tv_usec-timer.tv_usec;
  eventsUpdateTimers(delta);
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Descriptors; total=%d, actives=%d.\n",nb,status);
#endif
  void *wait_value=NULL;
  unsigned char wait_size=-1;
  if(FD_ISSET(waiting_room[0],&set)){
    read(waiting_room[0],&wait_size,sizeof(wait_size)); 
    if((wait_value=malloc(wait_size))==NULL)
      { perror("eventsScan.malloc"); exit(-1); }
    read(waiting_room[0],wait_value,wait_size);
#ifdef DEBUG_EVENTS
    fprintf(stderr,"Code received on wait pipe: ");
    eventsDisplayWaitValue(stderr,wait_size,wait_value);
    fprintf(stderr,".\n");
#endif
    }

  // Process events until no there is no active selector
  EventsEvent *event;
  EventsSelector *selector;
  while(1){
    unsigned char stop=1;
    for(i=0;i<events->events_nb;i++){
      event=events->events+i;
      int id_min=-1;
      int active=-1;
      for(j=0;j<event->selectors_nb;j++){
        selector=event->selectors+j;
        int id_cur=selector->identity;
        switch(selector->type){
          case EVENTS_ONDESCRIPTOR:{
            int fd=selector->selector.descriptor;
            if((id_min<0 || id_cur<id_min) && FD_ISSET(fd,&set))
              { active=j; id_min=id_cur; }
            }
            break;
          case EVENTS_ONTIMER:{
            long int time=selector->selector.timeout;
            if((id_min<0 || id_cur<id_min) && time==0)
              { active=j; id_min=id_cur; }
            }
            break;
          case EVENTS_ONTRIGGER:
            if(id_min<0 || id_cur<id_min)
              { active=j; id_min=id_cur; }
            break;
          case EVENTS_ONWAKE:
            if((id_min<0 || id_cur<id_min) &&
               selector->selector.wait_point.size==wait_size &&
               memcmp(selector->selector.wait_point.value,wait_value,wait_size)==0)
              { active=j; id_min=id_cur; }
            break;
          }
        }
      if(active>=0){
        stop=0;
        selector=event->selectors+active;
        switch(selector->type){
          case EVENTS_ONDESCRIPTOR:
            FD_CLR(selector->selector.descriptor,&set);
            break;
          }
#ifdef DEBUG_EVENTS
        switch(selector->type){
          case EVENTS_ONDESCRIPTOR:{
            int fd=selector->selector.descriptor;
            fprintf(stderr," Event #%d, selector #%d: active descriptor %d.\n",
                           i,active,fd);
            }
            break;
          case EVENTS_ONTIMER:{
            long int time=selector->selector.timeout;
            fprintf(stderr,"  Event #%d, selector #%d: expired timer %ldus.\n",
                           i,active,time);
            }
            break;
          case EVENTS_ONTRIGGER:
            fprintf(stderr,"  Event #%d, selector #%d: triggered.\n",i,active);
            break;
          case EVENTS_ONWAKE:{
            fprintf(stderr,"  Event #%d, selector #%d: wake value ",i,active);
            unsigned char size=selector->selector.wait_point.size;
            void *value=selector->selector.wait_point.value;
            eventsDisplayWaitValue(stderr,size,value);
            fprintf(stderr,".\n");
            }
            break;
          }
#endif
        eventsHandle(&event,&selector);
        }
      }
      if(stop==1) break;
    }

  // Free the waiting code
  if(wait_value) free(wait_value);
  }
// Close pipe for wait points
if(pipe(waiting_room)<0){ perror("eventsScan.pipe"); exit(-1); }
}

//
// Display wait point value
//
#ifdef DEBUG_EVENTS
static void eventsDisplayWaitValue(FILE *output,unsigned char size,void *value){
int i;
unsigned char *v=(unsigned char *)value;
for(i=0;i<size;i++) fprintf(output,"%02x",v[i]);
}
#endif

//
// Stub for reallocation with memory cleaning
//
static void *_realloc(void *ptr, size_t size){
void *result=realloc(ptr,size);
if(result==NULL && size>0) free(ptr);
return result;
}

