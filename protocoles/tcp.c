#include "tcp.h"
#include <stdio.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

// Définition des constantes TCP flags pour Linux (compatibilité BSD)
#ifndef TH_FIN
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#endif

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
    // Sur Linux, struct tcphdr utilise des bitfields, on doit les reconstruire manuellement
    *flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | 
             (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);

    //verbosite 2
    if (verbosity == 2) {
        printf("TCP: src_port=%u, dst_port=%u, seq=%u, ack=%u, flags=0x%02x\n",
               *src_port, *dst_port, 
               ntohl(tcp->seq), ntohl(tcp->ack_seq), *flags);
    }
    //verbosite 3
    else if (verbosity == 3) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("TCP Header:\n");
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Source Port:      %u\n", *src_port);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Destination Port: %u\n", *dst_port);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Sequence Number:  %u\n", ntohl(tcp->seq));

        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Acknowledgment Number: %u\n", ntohl(tcp->ack_seq));
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Data Offset: %u (%d bytes)\n", tcp->doff, tcp_header_len);
        
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
        
        // Options TCP (si présentes)
        if(tcp_header_len > 20){
            // Taille fixe de l'en-tête TCP de base = 20 octets
            int options_len = tcp_header_len - 20;
            
            if(options_len > 0) {
                for(int i = 0; i < indent+2; i++) printf(" ");
                printf("Options: %d bytes\n", options_len);
                
                // Afficher les options en hexadécimal si on a la place
                if(length >= tcp_header_len && options_len <= 40) {
                    const u_char *options = packet + 20;  // 20 = taille fixe en-tête TCP
                    for(int i = 0; i < indent+2; i++) printf(" ");
                    printf("  ");
                    for(int i = 0; i < options_len; i++) {
                        printf("%02x ", options[i]);
                        if((i + 1) % 16 == 0 && i < options_len - 1) {
                            printf("\n");
                            for(int j = 0; j < indent+2; j++) printf(" ");
                            printf("  ");
                        }
                    }
                    printf("\n");
                }
            }
        }
    }
    return tcp_header_len;
}

int tcp_v1_flags_summary(const u_char *packet, int caplen, int offset_transport, char *resume){
    if(caplen < offset_transport + (int)sizeof(struct tcphdr)) return 0;
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + offset_transport);
    unsigned int fl = (tcp->fin) | (tcp->syn<<1) | (tcp->rst<<2) | (tcp->psh<<3) | (tcp->ack<<4) | (tcp->urg<<5);
    if(fl & 0x02){ // SYN
        if(fl & 0x10){ if(strlen(resume)<240) strcat(resume, " SYN-ACK"); }
        else if(strlen(resume)<240) strcat(resume, " SYN");
    } else if(fl & 0x04){ if(strlen(resume)<240) strcat(resume, " RST"); }
    else if(fl & 0x01){ if(strlen(resume)<240) strcat(resume, " FIN"); }
    else if((fl & 0x08) && (fl & 0x10)){ if(strlen(resume)<240) strcat(resume, " PSH-ACK"); }
    else if(fl & 0x10){ if(strlen(resume)<240) strcat(resume, " ACK"); }
    return 1;
}
