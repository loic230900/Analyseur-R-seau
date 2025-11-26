#include "rarp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// Fonction de parsing
int parse_rarp(const u_char *packet, int length, int verbosity, int indent){
    if(length < 28){ // Taille minimale de l'en-tête RARP (identique à ARP)
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un en-tête RARP.\n");
        return 0;
    }
    // Extraction des champs de l'en-tête RARP (même structure que ARP)
    const struct ether_arp *rarp = (const struct ether_arp *)packet;
    uint16_t opcode = ntohs(rarp->ea_hdr.ar_op); // Operation code
    uint16_t hw_type = ntohs(rarp->ea_hdr.ar_hrd); // Hardware type
    uint16_t proto_type = ntohs(rarp->ea_hdr.ar_pro); // Protocol type

    // String d'opération (RARP utilise des opcodes spécifiques)
    const char *op_str = (opcode == ARPOP_RREQUEST) ? "Request" : 
                        (opcode == ARPOP_RREPLY) ? "Reply" : "Unknown";

    // Formatage des adresses MAC pour affichage
    char src_mac[18], dst_mac[18];
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             rarp->arp_tha[0], rarp->arp_tha[1], rarp->arp_tha[2],
             rarp->arp_tha[3], rarp->arp_tha[4], rarp->arp_tha[5]);
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             rarp->arp_sha[0], rarp->arp_sha[1], rarp->arp_sha[2],
             rarp->arp_sha[3], rarp->arp_sha[4], rarp->arp_sha[5]);

    // Formatage des adresses IP pour affichage
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    memcpy(&src_addr.s_addr, rarp->arp_spa, 4);
    memcpy(&dst_addr.s_addr, rarp->arp_tpa, 4);
    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

    // Verbosité 2 ligne synthétique
    if(verbosity == 2){
        for(int i = 0; i < indent; i++) printf(" ");
        if(opcode == ARPOP_RREQUEST){
            printf("RARP who-is %s tell %s\n", src_mac, dst_mac);
        } else if(opcode == ARPOP_RREPLY){
            printf("RARP %s is-at %s\n", src_ip, src_mac);
        } else {
            printf("RARP %s: %s (%s) -> %s (%s)\n", op_str, src_mac, src_ip, dst_mac, dst_ip);
        }
    }
    // Verbosité 3 détaillée
    else if (verbosity == 3) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("RARP: ");
        if(opcode == ARPOP_RREQUEST){
            printf("who-is %s tell %s\n", src_mac, dst_mac);
        } else if(opcode == ARPOP_RREPLY){
            printf("%s is-at %s\n", src_ip, src_mac);
        } else {
            printf("%s\n", op_str);
        }
        
        for(int i = 0; i < indent; i++) printf(" ");
        printf("RARP:\n");
        
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
    return 28; // Taille fixe de l'en-tête RARP (identique à ARP)
}

int rarp_v1_summary(const u_char *packet, int caplen, int offset_after_eth, char *resume){
    if(caplen < offset_after_eth + 28) return 0;
    const struct ether_arp *rarp = (const struct ether_arp *)(packet + offset_after_eth);
    uint16_t op = ntohs(rarp->ea_hdr.ar_op);
    
    if(op == ARPOP_RREQUEST){
        // RARP Request: "who-is <MAC> tell <MAC>"
        char smac[18], tmac[18];
        snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 rarp->arp_sha[0], rarp->arp_sha[1], rarp->arp_sha[2],
                 rarp->arp_sha[3], rarp->arp_sha[4], rarp->arp_sha[5]);
        snprintf(tmac, sizeof(tmac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 rarp->arp_tha[0], rarp->arp_tha[1], rarp->arp_tha[2],
                 rarp->arp_tha[3], rarp->arp_tha[4], rarp->arp_tha[5]);
        if(strlen(resume) < 240){
            strcat(resume, " who-is ");
            strcat(resume, smac);
            strcat(resume, " tell ");
            strcat(resume, tmac);
        }
        return 1;
    } else if(op == ARPOP_RREPLY){
        // RARP Reply: "<IP> is-at <MAC>"
        char sip[INET_ADDRSTRLEN];
        struct in_addr s;
        memcpy(&s.s_addr, rarp->arp_spa, 4);
        inet_ntop(AF_INET, &s, sip, sizeof(sip));
        char smac[18];
        snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 rarp->arp_sha[0], rarp->arp_sha[1], rarp->arp_sha[2],
                 rarp->arp_sha[3], rarp->arp_sha[4], rarp->arp_sha[5]);
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

