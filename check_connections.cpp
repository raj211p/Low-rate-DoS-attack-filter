#include <iostream>
#include <stdlib.h>
#include <cstdlib>
#include <string>
#include <string.h>
#include <cstring>
#include <stdio.h>
#include <thread>
#include "data.h"
#include <map>
#include <set>
using namespace std;
bool memflag=0, thflag=0, slow_get=0, slow_post=0, slow_read=0;
set<string> slow_get_ip;
set<string> slow_post_ip;
set<string> slow_read_ip;

// Bash command: netstat -tn 2>/dev/null | grep :80 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head


int main(int argc,char *argv[]){
    if(argc!=2){
        cout<<"Please specify the maximum number of connections a client can hold. Command format: <executable> --<limit>\n";
    }
    char *lim=argv[1];
    int connlimit=atoi(lim);
    string bashcmd="netstat -tn 2>/dev/null | grep :80 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr";
    map<string,int> m;
    thread th(thread_check); thread th2(ram_check); thread th3(slowloris); thread th4(slow_POST); thread th5(slow_Read);
    while(1){
    	FILE* pipe=popen(bashcmd.c_str(),"r");
        if(pipe==NULL){
            perror("pipe");
            exit(1);        
        }
        char buf[128]; string res=""; set<string> cur;
        while(fgets(buf,sizeof(buf),pipe)!=NULL){
            char *field;
            field=strtok(buf," "); //Outer
            int conns=0; bool flag=0; //0:number of connections, 1: IP addr.
            while(field!=NULL){    
                if(field=="\n"){
                    field=strtok(NULL," "); continue;
                }
                if(flag==0){
                   conns=atoi(field); 
                   //cout<<"\n"<<conns<<" conns, "; 
                   flag=1;
                }
                else if(flag==1){
                    string ip(field); ip.erase(ip.length()-1);
                    //cout<<"IP:"<<ip; cur.insert(ip);
                    flag=0;
                    m[ip]=conns;
                                    
                }
                field=strtok(NULL," ");
                
            }
            /*
            */
            
        }//Disconnected clients: in m, but not in cur
        pclose(pipe);

        if(thflag || memflag){
            
            if(slow_get){
                set<string> att;
                for(auto cl:slow_get_ip){
                    if(m.find(cl)!=m.end()){
                        if(m[cl]>connlimit){
                            string slow_GET_rule="sudo iptables -I INPUT -s ";
                            slow_GET_rule+=cl;
                            string rule_suff=" -j DROP"; slow_GET_rule+=rule_suff; char* rule1; //strcpy(rule1,slow_GET_rule.c_str());
                            cout<<"Blocking..\n";
                            system(slow_GET_rule.c_str());
                            att.insert(cl);
                        }
                    }
                    slow_get=0; memflag=0; thflag=0;
                }
                for(auto cl:att){
                    slow_get_ip.erase(cl);
                }
                
            }

            if(slow_post){
                set<string> att;
                for(auto cl:slow_post_ip){
                    if(m.find(cl)!=m.end()){
                        if(m[cl]>connlimit){
                            string slow_POST_rule="sudo iptables -I INPUT -s ";
                            slow_POST_rule+=cl;
                            string rule_suff=" -j DROP"; slow_POST_rule+=rule_suff; char* rule1; //strcpy(rule1,slow_POST_rule.c_str());
                            cout<<"Blocking..\n";
                            system(slow_POST_rule.c_str());
                            att.insert(cl);
                        }
                    }
                    slow_post=0; memflag=0; thflag=0;
                }
                for(auto cl:att){
                    slow_post_ip.erase(cl);
                }
                
            }
            
            if(slow_read){
                set<string> att;
                for(auto cl:slow_read_ip){
                    if(m.find(cl)!=m.end()){
                        if(m[cl]>connlimit){
                            string slow_Read_rule="sudo iptables -I INPUT -s ";
                            slow_Read_rule+=cl;
                            string rule_suff=" -j DROP"; slow_Read_rule+=rule_suff; char* rule1; //strcpy(rule1,slow_Read_rule.c_str());
                            cout<<"Blocking..\n";
                            system(slow_Read_rule.c_str());
                            att.insert(cl);
                        }
                    }
                    slow_read=0; memflag=0; thflag=0;
                }
                for(auto cl:att){
                    slow_read_ip.erase(cl);
                }
                
            }
        }        //thflag, memflag

        map<string,int>::iterator it;
        //cout<<"\nTable:\n"; 
        set<string> t;
        for(it=m.begin();it!=m.end();it++){
            if(cur.find(it->first)==cur.end()){ t.insert(it->first); }
        }
        for(auto s:t){ 
            m.erase(s); 
        }

    }    
    return 0;
}
