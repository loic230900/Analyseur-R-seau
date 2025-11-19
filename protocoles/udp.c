#include "udp.h"
#include <stdio.h>
#include <netinet/udp.h>
#include <string.h>

int parse_udp(const u_char *packet, int length, int verbosity, int indent, uint16_t *src_port, uint16_t *dst_port){
    if(length < (int)sizeof(struct udphdr)){
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un en-tête UDP.\n");
        return 0;
    }
    const struct udphdr *udp = (const struct udphdr *)packet;
    *src_port = ntohs(udp->source);
    *dst_port = ntohs(udp->dest);
    uint16_t udp_length = ntohs(udp->len);

    //verbosite 2 
    if (verbosity == 2) {
        // Niveau 2 : ligne synthétique
        for(int i = 0; i < indent; i++) printf(" ");
        printf("UDP: src_port=%u, dst_port=%u, length=%u\n", *src_port, *dst_port, udp_length);
    }
    //verbosite 3
    else if (verbosity == 3) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("UDP:\n");
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Source Port:      %u\n", *src_port);
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Destination Port: %u\n", *dst_port);
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Length:           %u\n", udp_length);
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Checksum:         0x%04x\n", ntohs(udp->uh_sum));
    }
    return sizeof(struct udphdr);
}

int udp_v1_ports_summary(const u_char *packet, int caplen, int offset_transport, char *resume){
    if(caplen < offset_transport + (int)sizeof(struct udphdr)) return 0;
    const struct udphdr *udp = (const struct udphdr *)(packet + offset_transport);
    uint16_t sp = ntohs(udp->source), dp = ntohs(udp->dest);
    char tmp[32]; snprintf(tmp,sizeof(tmp)," %u>%u", sp, dp);
    if(strlen(resume)+strlen(tmp) < 255) strcat(resume, tmp);
    return 1;
}