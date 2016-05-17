#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <math.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

uint16_t _bswap16(uint16_t a)
{
  a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
  return a;
}

void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);

    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--){
    unsigned short val=*buf;
    sum += _bswap16(val);
    buf++;
}
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}


/* Main function */
int main(int argc, char **argv)
{
  char ebuf[256];
  char  file_name[] = "/opt/DPDK-Replay/src/http_single.pcap";
  void * pkt;
  struct pcap_pkthdr *h;
  int ret = 1;
  int index =0 ;
  pcap_t *pt = pcap_open_offline(file_name, ebuf);
  if (pt == NULL){
    printf("Unable to open file: %s\n", file_name);
    return -1;
  }
  while(ret > 0 && index < 10){
    ret = pcap_next_ex(pt, &h, (const u_char**)&pkt);
   struct iphdr *iph; //ip header
   struct ip *ip; //ip
   iph = (struct iphdr*)(pkt + 14);
   ip = (struct ip*)(pkt + 14);
   const char* src_ip=inet_ntoa(*((struct in_addr*)&iph->saddr));
   const char* dst_ip=inet_ntoa(*((struct in_addr*)&iph->daddr));
   unsigned short check = iph->check;
   memset(&iph->check,0,2);
   unsigned short new_check = _bswap16(csum((unsigned short*)ip,10))
   printf("check:%#04x  new:%#04x  src:%s    dst:%s\n",check,new_check,src_ip,dst_ip);
   index++;
  }
 	pcap_close(pt);
}
