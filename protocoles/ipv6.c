#include "ipv6.h"
#include <stdio.h>
#include <string.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

int parse_ipv6(const u_char *packet, int length, int verbosity, int indent, uint8_t *next_hdr){
    if(length < (int)sizeof(struct ip6_hdr)) {
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un en-tête IPv6.\n");
        return 0;
    }
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)packet;
    *next_hdr = ip6->ip6_nxt;
    uint32_t v_tfl = ntohl(ip6->ip6_flow); // version, traffic class, flow label
    uint16_t payload_len = ntohs(ip6->ip6_plen); // longueur de la charge utile

    //conversion des adresses IP en texte
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip, sizeof(dst_ip));

    //verbosite 2 ligne synthethique
    if(verbosity == 2){
        printf("IPv6: src=%s, dst=%s, next_header=%u, hop_limit=%u\n", src_ip, dst_ip, ip6->ip6_nxt, ip6->ip6_hlim);
    }
    //verbosite 3 detaillee
    else if (verbosity == 3) {
        // Niveau 3 : affichage détaillé
        for(int i = 0; i < indent; i++) printf(" ");
        printf("IP:\n");
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Version: %u, TC: 0x%02x, Flow Label: 0x%05x\n",(v_tfl >> 28) & 0xF, (v_tfl >> 20) & 0xFF, v_tfl & 0xFFFFF);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Payload Length: %u, Next Header: %u, Hop Limit: %u\n",payload_len, ip6->ip6_nxt, ip6->ip6_hlim);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Source IP:      %s", src_ip);
        // Identifier les adresses spéciales IPv6
        if(strcmp(src_ip, "::") == 0 || strcmp(src_ip, "::1") == 0) printf(" [UNSPECIFIED/LOOPBACK]");
        else if(strncmp(src_ip, "ff", 2) == 0) printf(" [MULTICAST]");
        else if(strncmp(src_ip, "fe80:", 5) == 0) printf(" [LINK-LOCAL]");
        else if(strncmp(src_ip, "fc00:", 5) == 0 || strncmp(src_ip, "fd00:", 5) == 0) printf(" [UNIQUE-LOCAL]");
        printf("\n");
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Destination IP: %s", dst_ip);
        if(strcmp(dst_ip, "::") == 0 || strcmp(dst_ip, "::1") == 0) printf(" [UNSPECIFIED/LOOPBACK]");
        else if(strncmp(dst_ip, "ff", 2) == 0) printf(" [MULTICAST]");
        else if(strncmp(dst_ip, "fe80:", 5) == 0) printf(" [LINK-LOCAL]");
        else if(strncmp(dst_ip, "fc00:", 5) == 0 || strncmp(dst_ip, "fd00:", 5) == 0) printf(" [UNIQUE-LOCAL]");
        printf("\n");
    }
    return sizeof(struct ip6_hdr); // taille fixe de l'en-tête IPv6
}