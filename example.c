#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define SIZE 10
typedef unsigned long ulong;

void bar(char* log, char *someinput){
    char str[SIZE],user[SIZE];

    printf("[2] validate your name:\n>");
    scanf("%s",user);

    if(strncmp(user,"admin",5)){
        free(log); //relase the sensitive data
    }else{
        memcpy(log,someinput,10); //cache the sensitive data 
    }

    strcpy(str,someinput); 
    if(strncmp(user,"admin",5)){
        fprintf(stdout,"%s\n",str); // log for normal users 
    }else{
        system(str); //sensitive op of admin
    }
}



int main() {
    
    // alloc a place to record logs and some input
    char* log         = (char*) malloc(1024*sizeof(char));
    char* someinput   = (char*) malloc(1024*sizeof(char));

    // get user name
    printf("=============================[ service ]=========================\n");
    // get some input
    printf("[1] please enter some input:\n>");
    scanf("%s",someinput);

    // function
    bar(log,someinput);

    return 0;
}