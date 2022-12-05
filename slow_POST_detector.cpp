#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <set>
#include "data.h"
using namespace std;
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/*
 * print packet payload data (avoid printing binary data)
 */
void parse_payload_POST(char* payload, int len, string src_ip)
{
   char posth[5];
    //size_t ln=len;
   char s[5]="POST";
   for(int i=0;i<4;i++){
        posth[i]=*(payload+i);
    }
    posth[4]='\0';
    if(strcmp(posth,s)==0){
        //cout<<"\nPOST request detected.\n";
        char p[len]; strcpy(p,payload); //printf("%s",p);
        char exp[15]="Content-Length"; //14 (0-13)
        char* field=NULL; field=strtok(payload,"\r\n");
        while(field!=NULL){
            char hd[15];
            for(int i=0;i<14;i++){
                hd[i]=*(field+i); 
            } 
            hd[15]='\0';
            if(strcmp(exp,hd)==0){ 
                char* ln=strtok(field," "); ln=strtok(NULL," "); int cl=atoi(ln); 
                if(cl>=1000)
                    cout<<"Slow POST request detected! Source IP:"<<src_ip<<".\n";
                    slow_post_ip.insert(src_ip); slow_post=1;
            }
            //printf("%s",field);
            field=strtok(NULL,"\r\n"); 
        }
        
    }
}

/*
 * dissect/print packet
 */
void got_packet_POST(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1;                   /* packet counter */
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;
    
    //cout<<"\nPacket number :"<<count<<"\n";
    count++;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        cout<<"Invalid IP header length: "<<size_ip<<" bytes.\n";
        return;
    }

    /* print source and destination IP addresses */
    //cout<<"       From: "<<inet_ntoa(ip->ip_src)<<"\n";
    //cout<<"       To: "<<inet_ntoa(ip->ip_dst)<<"\n";
    string src_ip=inet_ntoa(ip->ip_src);
    if(strcmp(src_ip.c_str(),"10.0.2.19")==0)
    	return;   
    /* determine protocol */    
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            //cout<<"   Protocol: TCP\n";
            break;
        case IPPROTO_UDP:
            //cout<<"   Protocol: UDP\n";
            return;
        case IPPROTO_ICMP:
            //cout<<"   Protocol: ICMP\n";
            return;
        case IPPROTO_IP:
            //cout<<"   Protocol: IP\n";
            return;
        default:
            //cout<<"   Protocol: unknown\n";
            return;
    }
    
    /*
     *  OK, this packet is TCP.
     */
    
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    
    //printf("   Src port: %d\n", ntohs(tcp->th_sport));
    //printf("   Dst port: %d\n", ntohs(tcp->th_dport));
    
    /* define/compute tcp payload (segment) offset */
    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    
    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
       // printf("   Payload (%d bytes):\n", size_payload);
        parse_payload_POST(payload, size_payload, src_ip);
    }

return;
}

void slow_POST()
{

    char dev[7] = "enp0s3";            /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle;                /* packet capture handle */

    char filter_exp[] = "dst port 80";        /* filter expression [3] */
    struct bpf_program fp;            /* compiled filter program (expression) */
    bpf_u_int32 mask;            /* subnet mask */
    bpf_u_int32 net;            /* ip */
        
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet_POST, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

}
