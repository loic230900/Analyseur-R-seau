#define _DEFAULT_SOURCE
#include "tcp.h"
#include <stdio.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

int parse_tcp(const u_char *packet, int length, int verbosity, int indent, uint16_t *src_port, uint16_t *dst_port, uint8_t *flags){
    if(length < (int)sizeof(struct tcphdr)){
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un en-tête TCP.\n");
        return 0;
    }
    const struct tcphdr *tcp = (const struct tcphdr *)packet;
    *src_port = ntohs(tcp->source);
    *dst_port =ntohs(tcp->dest);
    
    //calcul de la taille de l'en-tête TCP
    int tcp_header_len = tcp->doff *4 ; //doff est le nombre de mots de 32 bits dans l'en-tête TCP
    if(length < tcp_header_len){
        fprintf(stderr, "Erreur: Paquet trop court pour contenir l'en-tête TCP complet.\n");
        return 0;
    }
    //extraction des flags TCP (1 octet contenant les 6 bits de contrôle)
    *flags = tcp->th_flags;

    //verbosite 2
    if (verbosity == 2) {
        printf("TCP: src_port=%u, dst_port=%u, seq=%u, ack=%u, flags=0x%02x\n",
               *src_port, *dst_port, 
               ntohl(tcp->seq), ntohl(tcp->ack_seq), *flags);
    }
    //verbosite 3
    else if (verbosity == 3) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("TCP:\n");
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Source Port:      %u\n", *src_port);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Destination Port: %u\n", *dst_port);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Sequence Number:  %u\n", ntohl(tcp->seq));

        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Acknowledgment Number: %u\n", ntohl(tcp->ack_seq));
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Data Offset: %u\n", tcp->doff);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Reserved: %u\n", tcp->res1);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Flags: 0x%02x (", *flags);
        //affichage des flags
        int first = 1;
        if(*flags & TH_FIN) { if(!first) printf(","); printf("FIN"); first = 0; }
        if(*flags & TH_SYN) { if(!first) printf(","); printf("SYN"); first = 0; }
        if(*flags & TH_RST) { if(!first) printf(","); printf("RST"); first = 0; }
        if(*flags & TH_PUSH) { if(!first) printf(","); printf("PSH"); first = 0; }
        if(*flags & TH_ACK) { if(!first) printf(","); printf("ACK"); first = 0; }
        if(*flags & TH_URG) { if(!first) printf(","); printf("URG"); first = 0; }
        printf(")\n");
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Window: %u\n", ntohs(tcp->window));
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Checksum: 0x%04x\n", ntohs(tcp->check));
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Urgent Pointer: %u\n", ntohs(tcp->urg_ptr));
        
        // Options display (if any)
        if(tcp_header_len > (int)sizeof(struct tcphdr)){
            int options_len = tcp_header_len - (int)sizeof(struct tcphdr);
            for(int i = 0; i < indent+2; i++) printf(" ");
            printf("Options: %d bytes\n", options_len);
        }
    }
    return tcp_header_len;
}
