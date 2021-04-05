#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>

#include "icmp_checksum.c"


int sockfd;
int seq = 0;
int send_num = 3;

u_int8_t buffer[4096] = {0};
struct ip *ip_hdr;

void ping_adress(char* adress, int ttl)
{
    setsockopt (sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
    
    struct icmp header;
    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;
    header.icmp_hun.ih_idseq.icd_id = getpid();//GET PID
    header.icmp_hun.ih_idseq.icd_seq = seq;//rand()%1000000000;
    header.icmp_cksum = 0;
    header.icmp_cksum = compute_icmp_checksum((u_int16_t*)&header, sizeof(header));

    struct sockaddr_in recipent;
    bzero (&recipent, sizeof(recipent));
    recipent.sin_family = AF_INET;
    inet_pton(AF_INET, adress, &recipent.sin_addr);

    ssize_t bytes_sent = sendto(
      sockfd,
      &header,
      sizeof(header),
      0,
      (struct sockaddr*)&recipent,
      sizeof(recipent)
    );  
}

int check_input(const char* in)
{
    char c = in[0];
    int it = 0;
    int dots = 0;

    while(c != '\0')
    {
        if(!isdigit(c))
        {
            if(c != '.')
                return 0;
            else
                dots += 1;
        }
        it+=1;
        c = in[it];
    }
    
    if(it > 15)
        return 0;
    if(dots != 3)
        return 0;

    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, in, &(sa.sin_addr));
    if(result != 0)
        return 1;
    else
        return 0;
}

char* get_IPV4(u_int32_t address)
{
    unsigned char b1 = (address & 0xFF000000)>>24;
    unsigned char b2 = (address & 0xFF0000)>>16;
    unsigned char b3 = (address & 0xFF00)>>8;
    unsigned char b4 = address & 0xFF;

    char* res = (char*)malloc(4*3 + 3 + 1);
    sprintf(res, "%u.%u.%u.%u", b4, b3, b2, b1);
    return res;
}

int rec_print(char** last_a)
{
    struct sockaddr_in 	sender;	
    socklen_t 			sender_len = sizeof(sender);

    fd_set descriptors;
    FD_ZERO (&descriptors);
    FD_SET (sockfd, &descriptors);
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    
    int ready = 0;
    float ms = 0.f;

    int asterix = 0;
    const char* output[send_num];
    int  output_it = 0;

    for(int i=0; i<send_num; i++)
    {
        clock_t start = clock();
        int cur = select (sockfd+1, &descriptors, NULL, NULL, &tv);
        if(cur == 0){
            asterix += 1;
        }
        else
        {
            ssize_t packet_len = recvfrom (sockfd, buffer, 4096, 0, (struct sockaddr*)&sender, &sender_len);
            if (packet_len < 0) {
                fprintf(stderr, "recvfrom error: %s\n", strerror(errno)); 
                return 0;
            }

            char sender_ip_str[20]; 
            inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
            /* printf ("Received IP packet with ICMP content from: %s\n", sender_ip_str); */

            struct ip* 			ip_header = (struct ip*) buffer;
            ssize_t				ip_header_len = 4 * ip_header->ip_hl;
            u_int8_t*           icmp_packet = buffer + ip_header_len;
            struct icmp*        icmp_header = (struct icmp*) icmp_packet;
            
            if(icmp_header->icmp_type == ICMP_TIMXCEED)
                icmp_header = (void*)icmp_header + 8 + ip_header_len;

            if(icmp_header->icmp_hun.ih_idseq.icd_id != getpid())
            {
                i-=1;
                continue;
            }

            struct in_addr ip_from_s = ip_header->ip_src;
            u_int32_t ip_from = ip_from_s.s_addr;
            const char* ip_hr = get_IPV4(ip_from);
            
            output[output_it] = ip_hr;
            if(strcmp(*last_a, ip_hr) == 0)
                return 0;

            output_it += 1;
        }
        
        clock_t end = clock();
        ready += 1;
        ms += ms+(float)(end-start)*1000.f/CLOCKS_PER_SEC;
    }

    if(asterix == send_num)
    {
        printf("*\n");
        return 1;
    }

    ms = ms/send_num;

    int count = ready;

    for(int i=0; i<count; i++)
    {
        if(!output[i])
            continue;
        *last_a = output[i];

        int already = 0;
        for(int j=0; j<i; j++)
        {
            if(strcmp(output[i], output[j]) == 0)
            {
                already = 1;
                break;
            }
        }
        if(already)
            break;
        printf("%s ", output[i]);
    }

    if(asterix == 0)
        printf("%0.2fms\n", ms);
    else
        printf("???\n");

    printf("\n");    
    return 1;
}

int main(int argc, char *argv[])
{
    srand(time(NULL));
    seq = rand() % 1000000;
    if(argc != 2)
    {
        printf("błędna liczba argumentów\n");
        return 0;
    }

    char* send_to = argv[1];

    if(!check_input(send_to))
    {
        printf("błędne dane wejściowe\n");
        return 0;
    }

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}

    char* last_address = "-1";
    int ttl = 1;
    while(true)
    {
        for(int k = 0; k < send_num; k++)
        {
            ping_adress(send_to, ttl);
        }
        int ret = rec_print(&last_address);
	    if(!ret)
            break;

        memset(buffer, 0, 4096);
        seq += 1;
        ttl += 1;
    }

	return EXIT_SUCCESS;
}
