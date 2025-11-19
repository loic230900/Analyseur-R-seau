#include "arp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

//fonction de parsing
int parse_arp(const u_char *packet, int length, int verbosity, int indent){
    if(length < 28){ //taille minimale de l'en-tête ARP
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un en-tête ARP.\n");
        return 0;
    }
    //extraction des champs de l'en-tête ARP
    const struct ether_arp *arp = (const struct ether_arp *)packet;
    uint16_t opcode = ntohs(arp->ea_hdr.ar_op); //operation code
    uint16_t hw_type = ntohs(arp->ea_hdr.ar_hrd); //hardware type
    uint16_t proto_type = ntohs(arp->ea_hdr.ar_pro); //protocol type

    //string d'operation
    const char *op_str = (opcode == ARPOP_REQUEST) ? "Request" : 
                        (opcode == ARPOP_REPLY) ? "Reply" : "Unknown";

    //Formatage des adresses MAC pour affichage
    char src_mac[18], dst_mac[18];
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
             arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
             arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

    //formatage des adresses IP pour affichage
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    memcpy(&src_addr.s_addr, arp->arp_spa, 4);
    memcpy(&dst_addr.s_addr, arp->arp_tpa, 4);
    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

    //verbosite 2 ligne synthethique
    if(verbosity == 2){
        printf("ARP %s: %s (%s) -> %s (%s)\n", op_str, src_ip, src_mac, dst_ip, dst_mac);
    }
    //verbosite 3 detaillee
    else if (verbosity == 3) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("ARP:\n");
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Operation:     %s (%u)\n", op_str, opcode);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Hardware Type: Ethernet (%u)\n", hw_type);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Protocol Type: IPv4 (0x%04x)\n", proto_type);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Sender MAC:    %s\n", src_mac);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Sender IP:     %s\n", src_ip);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Target MAC:    %s\n", dst_mac);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Target IP:     %s\n", dst_ip);
    }
    return 28; //taille fixe de l'en-tête ARP
}

int arp_v1_summary(const u_char *packet, int caplen, int offset_after_eth, char *resume){
    if(caplen < offset_after_eth + 28) return 0;
    const struct ether_arp *arp = (const struct ether_arp *)(packet + offset_after_eth);
    uint16_t op = ntohs(arp->ea_hdr.ar_op);
    if(op == ARPOP_REQUEST){
        char sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
        struct in_addr s,t;
        memcpy(&s.s_addr, arp->arp_spa, 4);
        memcpy(&t.s_addr, arp->arp_tpa, 4);
        inet_ntop(AF_INET, &s, sip, sizeof(sip));
        inet_ntop(AF_INET, &t, tip, sizeof(tip));
        if(strlen(resume) < 240){
            strcat(resume, " who-has ");
            strcat(resume, tip);
            strcat(resume, " tell ");
            strcat(resume, sip);
        }
        return 1;
    } else if(op == ARPOP_REPLY){
        char sip[INET_ADDRSTRLEN]; struct in_addr s;
        memcpy(&s.s_addr, arp->arp_spa, 4);
        inet_ntop(AF_INET, &s, sip, sizeof(sip));
        char smac[18];
        snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                 arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
        if(strlen(resume) < 240){
            strcat(resume, " ");
            strcat(resume, sip);
            strcat(resume, " is-at ");
            strcat(resume, smac);
        }
        return 1;
    }
    return 0;
}