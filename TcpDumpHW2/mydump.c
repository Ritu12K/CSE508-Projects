#include <pcap.h>
#include<time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define ICMP_HDR_SIZE 8

#define UDP_HDR_SIZE 8

#define	ETHERTYPE_PUP		0x0200      /* Xerox PUP */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */


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

// /*udp_header*/
// struct sniff_udp {
// 	u_short	uh_sport;		/* source port */
// 	u_short	uh_dport;		/* destination port */
// 	u_short	uh_ulen;		/* datagram length */
// 	u_short	uh_sum;			/* datagram checksum */
// };
//

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

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

char* myStrStr(u_char *str, u_char *target, int length);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
  printf("\n");
return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	for ( ;; ) {
		line_len = line_width % len_rem;
		print_hex_ascii_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*strstr implementation*/
char *myStrStr(u_char *str, u_char *target, int length) {
  u_char *payload=str;
  u_char *mystr=target;
  int i;
    while(length){
       if(*payload == *mystr){
           for(i=0;i<strlen((const char *)mystr);i++){
             if(*(payload+i)!= *(mystr+i)){
               break;
             }
           }
           if(i==strlen((const char *)mystr)){
             return (char *)payload;
           }
       }
     payload++;
     length--;
   }
return NULL;
}

/*
 * dissect/print packet
 */

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

  char *sbstr=(char *)args;

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
  const struct icmphdr* icmphdr;
  const struct udphdr* udphdr;

	const char *payload;                    /* Packet payload */
  struct timeval tv;
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[64], buf[64];
  u_char *ptr;
  int i;
  char* p;
  char *str1;
  char *str2;
  int packettype;

	int size_ip;
	int size_tcp;
  int size_icmp;
  int size_udp;
	int size_payload;
  int packet_size;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;


  if (ntohs (ethernet->ether_type) != ETHERTYPE_IP)
    {
          payload = (const char *)(packet + SIZE_ETHERNET);
          size_payload = (header->len) - (SIZE_ETHERNET);

          if(sbstr){
            p = myStrStr((u_char*)payload,(u_char*)sbstr,size_payload);
            if(p){
              printf("\n");
              tv = header->ts;

              gettimeofday(&tv, NULL);
              nowtime = header->ts.tv_sec;
              nowtm = localtime(&nowtime);
              strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
              snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, header->ts.tv_usec);

              printf("%s ", buf);

              ptr = (u_char *)(ethernet->ether_shost);
              i = ETHER_ADDR_LEN;
              do{
                  printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
              }while(--i>0);

               printf("->");

               ptr = (u_char *)(ethernet->ether_dhost);
               i = ETHER_ADDR_LEN;
               do{
                   printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
               }while(--i>0);


                printf(" type 0x0%x", ntohs(ethernet->ether_type));
                printf(" len %d",header->len);

                if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP){
                  printf(" ARP ");
                }
                printf("Payload size: %d bytes\n", size_payload);
                if (size_payload > 0) {
                  printf("\n");
                      print_payload((const u_char *)payload, size_payload);
                  }
            }
          }
          else{
            printf("\n");
            tv = header->ts;

            gettimeofday(&tv, NULL);
            nowtime = header->ts.tv_sec;
            nowtm = localtime(&nowtime);
            strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
            snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, header->ts.tv_usec);

            printf("%s ", buf);

            ptr = (u_char *)(ethernet->ether_shost);
            i = ETHER_ADDR_LEN;
            do{
                printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
            }while(--i>0);

             printf("->");

             ptr = (u_char *)(ethernet->ether_dhost);
             i = ETHER_ADDR_LEN;
             do{
                 printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
             }while(--i>0);


              printf(" type 0x0%x", ntohs(ethernet->ether_type));
              printf(" len %d",header->len);

              if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP){
                printf(" ARP ");
              }
              printf("Payload size: %d bytes\n", size_payload);
              if (size_payload > 0) {
                printf("\n");
                    print_payload((const u_char *)payload, size_payload);
                }
          }

            return;
}


	/* determine protocol */
	  switch(ip->ip_p) {
		case IPPROTO_TCP:
      tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      payload = (const char *)(packet + SIZE_ETHERNET+ size_ip + size_tcp);
      size_payload = ntohs(ip->ip_len) - (size_ip+size_tcp);
			break;

  		case IPPROTO_UDP:
      udphdr= (struct udphdr*)(packet+ SIZE_ETHERNET + size_ip);
      size_udp = UDP_HDR_SIZE;
      payload = (const char *)(packet + SIZE_ETHERNET+ size_ip + size_udp);
      size_payload = ntohs(ip->ip_len) - (size_ip+size_udp);
      break;


		  case IPPROTO_ICMP:
      icmphdr= (struct icmphdr*)(packet+ SIZE_ETHERNET + size_ip);
      size_icmp = ICMP_HDR_SIZE;
      payload = (const char *)(packet + SIZE_ETHERNET+ size_ip + size_icmp);
      size_payload = ntohs(ip->ip_len) - (size_ip+size_icmp);
			break;

		  case IPPROTO_IP:
      payload = (const char *)(packet + SIZE_ETHERNET+ size_ip);
      size_payload = ntohs(ip->ip_len) - (size_ip);
			break;

		  default:
      payload = (const char *)(packet + SIZE_ETHERNET+ size_ip);
      size_payload = ntohs(ip->ip_len) - (size_ip);
			break;
	}


    if(sbstr){
      p = myStrStr((u_char*)payload,(u_char*)sbstr,size_payload);
      if(p){
        printf("\n");
      	tv = header->ts;

      	gettimeofday(&tv, NULL);
      	nowtime = header->ts.tv_sec;
      	nowtm = localtime(&nowtime);
      	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
      	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, header->ts.tv_usec);

      	printf("%s ", buf);

        ptr = (u_char *)(ethernet->ether_shost);
        i = ETHER_ADDR_LEN;
        do{
            printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);

         printf("->");

         ptr = (u_char *)(ethernet->ether_dhost);
         i = ETHER_ADDR_LEN;
         do{
             printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
         }while(--i>0);


           printf(" type 0x0%x", ntohs(ethernet->ether_type));
           printf(" len %d",header->len);

           switch(ip->ip_p) {
         		case IPPROTO_TCP:
               printf("\n%s:%d", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
               printf("->");
               printf(" %s:%d ", inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));
               printf(" TCP\n");
         			break;

           		case IPPROTO_UDP:
               printf("\n%s:%d", inet_ntoa(ip->ip_src),ntohs(udphdr->uh_sport));
               printf("->");
               printf(" %s:%d ", inet_ntoa(ip->ip_dst),ntohs(udphdr->uh_dport));
               printf(" UDP\n");
               break;


         		  case IPPROTO_ICMP:
               printf("\n%s", inet_ntoa(ip->ip_src));
               printf("->");
               printf(" %s", inet_ntoa(ip->ip_dst));
               printf(" ICMP\n");
         			break;

         		  case IPPROTO_IP:
              printf("\n%s", inet_ntoa(ip->ip_src));
              printf("->");
              printf(" %s", inet_ntoa(ip->ip_dst));
         			printf("IP\n");
         			break;

         		  default:
              printf("\n%s", inet_ntoa(ip->ip_src));
              printf("->");
              printf(" %s", inet_ntoa(ip->ip_dst));
         			printf("OTHERS\n");
         			break;
         	}
           printf("Payload size:%d bytes\n", size_payload);
        	 if (size_payload > 0) {
           print_payload((const u_char *)payload, size_payload);
           printf("\n");
         }
      }
    }
    else{
      printf("\n");
	    tv = header->ts;

    	gettimeofday(&tv, NULL);
    	nowtime = header->ts.tv_sec;
    	nowtm = localtime(&nowtime);
    	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
    	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, header->ts.tv_usec);

    	printf("%s ", buf);

      ptr = (u_char *)(ethernet->ether_shost);
      i = ETHER_ADDR_LEN;
      do{
          printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
      }while(--i>0);

       printf("->");

       ptr = (u_char *)(ethernet->ether_dhost);
       i = ETHER_ADDR_LEN;
       do{
           printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
       }while(--i>0);


         printf(" type 0x0%x", ntohs(ethernet->ether_type));
         printf(" len %d",header->len);



         switch(ip->ip_p) {
       		case IPPROTO_TCP:
             printf(" \n%s:%d", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
             printf("->");
             printf(" %s:%d ", inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));
             printf(" TCP\n");
       			break;

         		case IPPROTO_UDP:
             printf(" \n%s:%d", inet_ntoa(ip->ip_src),ntohs(udphdr->uh_sport));
             printf("->");
             printf(" %s:%d ", inet_ntoa(ip->ip_dst),ntohs(udphdr->uh_dport));
             printf(" UDP\n");
             break;


       		  case IPPROTO_ICMP:
             printf(" \n%s", inet_ntoa(ip->ip_src));
             printf("->");
             printf(" %s", inet_ntoa(ip->ip_dst));
             printf(" ICMP\n");
       			break;

       		  case IPPROTO_IP:
            printf(" \n%s", inet_ntoa(ip->ip_src));
            printf("->");
            printf(" %s", inet_ntoa(ip->ip_dst));
       			printf("IP\n");
       			break;

       		  default:
       			printf("OTHER\n");
            printf(" \n%s", inet_ntoa(ip->ip_src));
            printf("->");
            printf(" %s", inet_ntoa(ip->ip_dst));
       			printf("OTHERS\n");
       			break;
       	}

      printf("Payload size:%d bytes\n", size_payload);
      	if (size_payload > 0) {

        print_payload((const u_char *)payload, size_payload);
        printf("\n");
      }
    }


return;
}

int main(int argc, char **argv)
{
	char *dev = NULL;
	char *substring= NULL;
	char *readfile= NULL;
	char *filter_name=NULL;
	int c;	/* capture device name */
  int index;
  char *p;
  bool exp=false;
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;
  		/* packet capture handle */

	char filter_exp[20];		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;
				/* number of packets to capture */
     while ((c = getopt (argc, argv, "i:r:s:")) != -1)
        switch (c)
          {
          case 'i':
            dev = optarg;
            break;
          case 'r':
            readfile = optarg;
            break;
          case 's':
            substring = optarg;
            break;
          case '?':
            if (optopt == 'i'|| optopt == 'r' || optopt == 's' )
              fprintf (stderr, "Option -%c requires an argument.\n",optopt);
            else if (isprint (optopt))
              fprintf (stderr, "Unknown option `-%c'.\n",optopt);
            else
              fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
            return 1;
          default:
            abort ();
          }

      for (index = optind; index < argc; index++){
        if(optind==index){
          filter_name=argv[index];
          exp=true;
          //memset(buf,0,sizeof buf);
          strncpy(filter_exp,filter_name,(sizeof filter_exp)-1);
          p=&filter_exp[0];
        }
    }

	/* check for capture device name on command-line */
	if (dev == NULL) {
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n",
          errbuf);
      exit(EXIT_FAILURE);
    }
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}


if(readfile!= NULL){
  handle = pcap_open_offline(readfile, errbuf);
  if (handle == NULL) {
  fprintf(stderr, "pcap_open_offline() failed: %s\n",errbuf);
  exit(EXIT_FAILURE);
  }
}
else{
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }
}
/* open capture device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}
	/* apply the compiled filter */
  if(exp){
/* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n",
          filter_exp, pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n",
          filter_exp, pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }

  }

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, (u_char *)substring);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
