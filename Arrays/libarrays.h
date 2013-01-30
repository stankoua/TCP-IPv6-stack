/*
 * Common definitions for handling associative arrays
 */

////
// Constants
////

#define		AARRAY_NUMERIC_INDEX	1
#define		AARRAY_COMPACT_VALUE	2
#define		AARRAY_DONT_FREE	4
#define		AARRAY_END_OF_ARRAY	8

#define		AARRAY_FORCE_NUMERIC	1
#define		AARRAY_DONT_COMPACT	2
#define		AARRAY_DONT_DUPLICATE	4

////
// Macros
////

#define		AARRAY_MSETVAR(a,i)	arraysSetValue(&(a),#i,&(i),sizeof(i),0)
#define		AARRAY_FSETVAR(a,i,v)	arraysSetValue(&(a),#i,&(v),sizeof(v),0)
#define		AARRAY_MSETREF(a,i)	arraysSetValue(&(a),#i,i,i##_size,AARRAY_DONT_DUPLICATE)
#define		AARRAY_FSETREF(a,i,p,s)	arraysSetValue(&(a),#i,p,s,AARRAY_DONT_DUPLICATE)
#define		AARRAY_MGETVAR(a,i,t)	t i=*((t *)arraysGetValue(a,#i,NULL,0))
#define		AARRAY_HGETVAR(a,i,t,v)	v=*((t *)arraysGetValue(a,#i,NULL,0))
#define		AARRAY_FGETVAR(a,i,t,v)	t v=*((t *)arraysGetValue(a,#i,NULL,0))
#define		AARRAY_MGETREF(a,i,t)	int i##_size; t i=(t)arraysGetValue(a,#i,&i##_size,0)
#define		AARRAY_HGETREF(a,i,t,v)	t v=(t)arraysGetValue(a,#i,NULL,0)
#define		AARRAY_FGETREF(a,i,t,v,s)	\
			int s; t v=(t)arraysGetValue(a,#i,&(s),0)

////
// Structures
////

typedef struct{
  unsigned char flags;
  char *index;
  void *data;
  int size;
  } AssocArray;

////
// Prototypes
////

int arraysGetLength(AssocArray *array);
int arraysGetSize(AssocArray *array);
int arraysTestIndex(AssocArray *array,char *index,unsigned char flags);
void *arraysGetValue(
  AssocArray *array,char *index,int *size,unsigned char flags);
int arraysSetValue(
  AssocArray **array,char *index,void *data,int size,unsigned char flags);
AssocArray *arraysCopyArray(AssocArray *array,unsigned char full);
void arraysFreeArray(AssocArray *array);
void arraysDisplayArray(FILE *output,AssocArray *array);
