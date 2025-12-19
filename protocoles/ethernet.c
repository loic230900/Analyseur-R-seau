/**
 * @file ethernet.c
 * @brief Analyseur de trames Ethernet (couche 2 - Liaison de données)
 * 
 * Ce module implémente le parsing des trames Ethernet II (IEEE 802.3).
 * L'en-tête Ethernet fait 14 octets : MAC dst (6) + MAC src (6) + EtherType (2)
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "ethernet.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "../util/textutils.h"

/* LLDP n'est pas toujours défini dans les headers système */
#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88CC
#endif

/**
 * Retourne le nom lisible d'un EtherType
 * @param type Code EtherType (2 octets, ordre hôte)
 * @return Nom du protocole ou NULL si inconnu
 */
const char* get_ethertype_name(uint16_t type) {
    switch(type) {
        case ETHERTYPE_IP: return "IPv4";
        case ETHERTYPE_IPV6: return "IPv6";
        case ETHERTYPE_ARP: return "ARP";
        case ETHERTYPE_REVARP: return "RARP";
        case ETHERTYPE_VLAN: return "802.1Q VLAN";
        case ETHERTYPE_LLDP: return "LLDP";
        default: return NULL;
    }
}

int parse_ethernet(const u_char *packet, int length, int verbosity, int indent, uint16_t *ethertype){
    if (length < ETHER_HDR_LEN) {
        fprintf(stderr, "Ethernet: Packet too short for header (need %d, got %d)\n", ETHER_HDR_LEN, length);
        return 0;
    }
    const struct ether_header *eth = (struct ether_header *)packet;
    *ethertype = ntohs(eth->ether_type);
 
    /* Formatage des adresses MAC en notation hexadécimale standard (xx:xx:xx:xx:xx:xx) */
    char src_mac[18], dst_mac[18];
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
             eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
             eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    
    /* Récupérer le nom lisible du type Ethernet */
    const char* type_name = get_ethertype_name(*ethertype);
    
    /* Verbosité 2 : affichage synthétique sur une ligne */
    if(verbosity == 2){
        print_indent(indent);
        if(type_name) {
            printf("Ethernet: %s -> %s [type=%s]\n", src_mac, dst_mac, type_name);
        } else {
            printf("Ethernet: %s -> %s [type=0x%04x]\n", src_mac, dst_mac, *ethertype);
        }
    }
    /* Verbosité 3 : affichage détaillé avec indicateur de couche OSI */
    else if (verbosity == 3){
        print_indent(indent);
        printf("[L2] Ethernet Header:\n");
        print_indent(indent);
        printf("      MAC Flow:     %s -> %s\n", src_mac, dst_mac);
        print_indent(indent);
        if(type_name) {
            printf("      EtherType:    0x%04x (%s)\n", *ethertype, type_name);
        } else {
            printf("      EtherType:    0x%04x\n", *ethertype);
        }
    }
    return ETHER_HDR_LEN;
}