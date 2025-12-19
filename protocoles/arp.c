/**
 * Parsing des messages ARP conformément à la RFC 826.
 * 
 * EtherType : 0x0806
 */

#include "arp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../util/safe_string.h"
#include "../util/display_constants.h"
#include "../util/textutils.h"

// Analyse et affiche les champs de l'en-tête ARP.

int parse_arp(const u_char *packet, int length, int verbosity, int indent){
    if(length < ARP_HDR_LEN){ //taille minimale de l'en-tête ARP
        fprintf(stderr, "ARP: Packet too short for ARP header (need %d, got %d)\n", ARP_HDR_LEN, length);
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
    //dst
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
             arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
    //src
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
             arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

    //formatage des adresses IP pour affichage
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    memcpy(&src_addr.s_addr, arp->arp_spa, 4); // on copie les 4 octets de l'adresse IP source
    memcpy(&dst_addr.s_addr, arp->arp_tpa, 4);
    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip)); // conversion en chaîne lisible
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

    /* Verbosité 2: ligne synthétique */
    if(verbosity == 2){
        print_indent(indent);
        if(opcode == ARPOP_REQUEST){
            printf("ARP who-has %s tell %s\n", dst_ip, src_ip);
        } else if(opcode == ARPOP_REPLY){
            printf("ARP %s is-at %s\n", src_ip, src_mac);
        } else {
            printf("ARP %s: %s (%s) -> %s (%s)\n", op_str, src_ip, src_mac, dst_ip, dst_mac);
        }
    }
    /* Verbosité 3: affichage détaillé */
    else if (verbosity == 3) {
        print_indent(indent);
        printf("[L2] ARP Header:\n");
        if(opcode == ARPOP_REQUEST){
            print_indent(indent);
            printf("      Summary: who-has %s tell %s\n", dst_ip, src_ip);
        } else if(opcode == ARPOP_REPLY){
            print_indent(indent);
            printf("      Summary: %s is-at %s\n", src_ip, src_mac);
        } else {
            print_indent(indent);
            printf("      Summary: %s\n", op_str);
        }
        
        print_indent(indent);
        printf("      Operation:    %s (%u)\n", op_str, opcode);
        
        print_indent(indent);
        printf("      Hardware:     Ethernet (%u)\n", hw_type);
        
        print_indent(indent);
        printf("      Protocol:     IPv4 (0x%04x)\n", proto_type);
        
        print_indent(indent);
        printf("      Sender MAC:   %s\n", src_mac);
        
        print_indent(indent);
        printf("      Sender IP:    %s\n", src_ip);
        
        print_indent(indent);
        printf("      Target MAC:   %s\n", dst_mac);
        
        print_indent(indent);
        printf("      Target IP:    %s\n", dst_ip);
    }
    return ARP_HDR_LEN;
}

// Verbosité 1: ajoute résumé ARP (who-has/is-at) au buffer résumé.

int arp_v1_summary(const u_char *packet, int caplen, int offset_after_eth, char *resume){
    if(caplen < offset_after_eth + ARP_HDR_LEN) return 0; //pas assez de données pour l'en-tête ARP

    const struct ether_arp *arp = (const struct ether_arp *)(packet + offset_after_eth); //pointeur vers l'en-tête ARP

    //extraction du code d'opération
    uint16_t op = ntohs(arp->ea_hdr.ar_op);

    //construction du résumé selon le type d'opération
    if(op == ARPOP_REQUEST){                                //requête ARP
        char sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN]; //adresses IP source et cible
        struct in_addr s,t; //structures pour conversion
        memcpy(&s.s_addr, arp->arp_spa, 4);
        memcpy(&t.s_addr, arp->arp_tpa, 4);
        inet_ntop(AF_INET, &s, sip, sizeof(sip));
        inet_ntop(AF_INET, &t, tip, sizeof(tip));

        //ajout au résumé avec mes fonctions can_append et safe_strcat
        if(can_append(resume, " who-has ", RESUME_BUFFER_SIZE)){
            safe_strcat(resume, " who-has ", RESUME_BUFFER_SIZE);
            safe_strcat(resume, tip, RESUME_BUFFER_SIZE);
            safe_strcat(resume, " tell ", RESUME_BUFFER_SIZE);
            safe_strcat(resume, sip, RESUME_BUFFER_SIZE);
        }
        return 1;

    } else if(op == ARPOP_REPLY){                           //réponse ARP
        char sip[INET_ADDRSTRLEN]; struct in_addr s;
        memcpy(&s.s_addr, arp->arp_spa, 4);
        inet_ntop(AF_INET, &s, sip, sizeof(sip));

        char smac[18];                                      //adresse MAC source

        //formatage de l'adresse MAC source
        snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                 arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
    
        //ajout au résumé 
        if(can_append(resume, " ", RESUME_BUFFER_SIZE)){
            safe_strcat(resume, " ", RESUME_BUFFER_SIZE);
            safe_strcat(resume, sip, RESUME_BUFFER_SIZE);
            safe_strcat(resume, " is-at ", RESUME_BUFFER_SIZE);
            safe_strcat(resume, smac, RESUME_BUFFER_SIZE);
        }
        return 1;
    }
    return 0;
}