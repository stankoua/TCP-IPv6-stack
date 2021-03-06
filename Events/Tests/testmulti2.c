/* Test file for events */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libevents.h"

////
// Constants
////
#define MAX_LINE	1024
#define MAX_STRING	128

////
// Global variables
////
int event_main;
int event_helper;

////
// Functions
////

//
// Main event action
//

unsigned char action(EventsEvent *event,EventsSelector *selector){
// Display selector message
char *string=(char *)selector->data_this;
fprintf(stdout,"Message from selector:\n%s\n",string);
free(string);
return 0;
}

//
// Helper action to fire up main action
//

unsigned char helper(EventsEvent *event,EventsSelector *selector){
// Get signal to activate
int *signal=(int *)selector->data_this;
eventsSignalStandby(*signal);
// Read input if needed
if(selector->type==EVENTS_ONDESCRIPTOR){
  char buffer[MAX_LINE];
  fgets(buffer,MAX_LINE,stdin);
  printf("Text: %s",buffer);
  }
return 1;
}


////
// Main procedure
////

int main(void){
char *text1="Les cloîtres anciens sur leurs grandes murailles\n\
Etalaient en tableaux la sainte Vérité,\n\
Dont l'effet réchauffant les pieuses entrailles,\n\
Tempérait la froideur de leur austérité.\n\
\n\
En ces temps où du Christ florissaient les semailles,\n\
Plus d'un illustre moine, aujourd'hui peu cité,\n\
Prenant pour atelier le champ des funérailles,\n\
Glorifiait la Mort avec simplicité.\n\
\n\
- Mon âme est un tombeau que, mauvais cénobite,\n\
Depuis l'éternité je parcours et j'habite;\n\
Rien n'embellit les murs de ce cloître odieux.\n\
\n\
O moine fainéant! quand saurai-je donc faire\n\
Du spectacle vivant de ma triste misère\n\
Le travail de mes mains et l'amour de mes yeux?";
char *text2="La Nature est une temple où de vivants piliers\n\
Laissent parfois sortir de confuses paroles;\n\
L'homme y passe à travers des forêts de symboles\n\
Qui l'observent avec des regards familiers.\n\
\n\
Comme des longs échos qui de loin se confondent\n\
Dans une ténébreuse et profonde unité,\n\
Vaste comme la nuit et comme la clarté,\n\
Les parfums, les couleurs et les sons se répondent.\n\
\n\
Il est des parfums frais comme des chairs d'enfants,\n\
Doux comme des hautbois, verts comme des prairies,\n\
-Et d'autre corrompus, riches et triomphants,\n\
\n\
Ayant l'expansion des choses infinies,\n\
Comme l'ambre, le musc, le benjoin et l'encens,\n\
Qui chantent les transports de l'esprit et des sens.";
event_main=eventsCreate(0,NULL);
event_helper=eventsCreate(1,NULL);
eventsAddAction(event_main,action,0);
eventsAddAction(event_helper,helper,0);
char *message1=(char *)malloc(strlen(text1));
strcpy(message1,text1);
int signal1=eventsStandby(event_main,message1);
char *message2=(char *)malloc(strlen(text2));
strcpy(message2,text2);
int signal2=eventsStandby(event_main,message2);
eventsAssociateDescriptor(event_helper,0,&signal1);
eventsAssociateDescriptor(event_helper,0,&signal2);
eventsSchedule(event_helper,30000000,&signal1);
eventsSchedule(event_helper,60000000,&signal2);
eventsScan();
exit(0);
}

