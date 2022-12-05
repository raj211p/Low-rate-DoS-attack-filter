#include<stdio.h>
#include<iostream>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include "data.h"
using namespace std;

void thcount(int i){
    char bashcmd[512]="ps hH -u www-data | wc -l";
    FILE *pipe;
    int ln, prev, cur;

    while(1){
        pipe=popen(bashcmd,"r");
        if(pipe==NULL){
            perror("pipe");
            exit(1);        
        }
        char buf[5];
        fgets(buf,sizeof(buf),pipe);
        ln=strlen(buf); buf[ln-1]='\0';
        char *ptr;
        long thc;
        if(i==0){
            prev=strtol(buf,&ptr,10); cur=prev; i=1;
        }
        else{
            //prev=cur;
            cur=strtol(buf,&ptr,10);
            if(cur-prev>5){
                //cout<<"Spike detected!\n"; 
                thflag=1;
            }
            prev=cur;
        }
        
        sleep(1);
        pclose(pipe);
    }

}

void thread_check(){
    thcount(0);

}
