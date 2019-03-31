#include <pcap.h>
#include <stdio.h>
#include "pcapheader.h"
#include <stdint.h>
#include <arpa/inet.h>

void tcp(const u_char * packet)
{
    struct  ip_header * iphdr = (struct ip_header *)(packet + 14);
    struct tcp_header * tcphdr = (struct tcp_header *)(packet + 14 + iphdr->ihl*4 );

        printf("TCP header length : %d \n",(tcphdr->doff)*4);
        printf("sport : %u \n",ntohs(tcphdr->sport));
        printf("dport : %u \n",ntohs(tcphdr->dport));
        //**
        const u_char * http = (u_char *)(packet + 14 + iphdr->ihl*4 + tcphdr->doff*4);
        int cnt = iphdr->tot_len - iphdr->ihl - tcphdr->doff *4;
        printf("HTTP data : ");
        if(cnt >16)
            for(int i = 0; i < 16; i++)
            {
                printf("%c",*(http+i));
            }
        else
            for(int i = 0; i < cnt; i++)
            {
                printf("%c",*(http+i));
            }

        printf("\n");
        printf("HTTP data length : %d \n",  ntohs(iphdr->tot_len - iphdr->ihl - tcphdr->doff *4));


}


void ip(const u_char * packet)
{
    char buf[20];
    struct  ip_header * iphdr = (struct ip_header *)(packet + 14);
    printf("ip header Length : %d \n",iphdr->ihl*4);
    printf("sip : %s\n",inet_ntop(AF_INET,&iphdr->saddr,buf,sizeof(buf)));
    printf("dip : %s\n",inet_ntop(AF_INET,&iphdr->daddr,buf,sizeof(buf)));
    printf("     Next type : TCP \n");
    tcp(packet);
}

void dsmac(uint8_t addr[],int x)
{
    if(x == 1)
        printf("dmac :");
    if(x == 2)
        printf("smac :");

    for(int i = 0; i<6; i++)
    {
        printf("%02x",addr[i]);
        if(i <= 4)
            printf(": ");
        else
            printf("\n");
    }
}


void mac(const u_char * packet)
{
    struct ether_header * ethhdr = (struct ether_header *) packet;
    struct  ip_header * iphdr = (struct ip_header *)(packet + 14);
    struct tcp_header * tcphdr = (struct tcp_header *)(packet + 14 + iphdr->ihl*4 );


    if(ntohs(ethhdr->ether_type) == 0x0800 && iphdr->protocol == 6 && (tcphdr->dport || tcphdr->sport == 80))
    {
        printf("---------------------------------------\n");
        printf("     EtherNet\n");
        dsmac(ethhdr->ether_dmac,1);
        dsmac(ethhdr->ether_smac,2);
        printf("     Next type: IP \n");
        ip(packet);
        printf("---------------------------------------\n");

    }
}





void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    mac(packet);
     }

  pcap_close(handle);
  return 0;
}
