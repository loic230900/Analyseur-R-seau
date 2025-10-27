#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <pcap.h>
#include <net/if_arp.h>

//Types Ethernet
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

//strutcture ARP pour ethernet
struct ether_arp {
    struct arphdr ea_hdr;  //en-tête ARP standard
    uint8_t arp_sha[6];  //sender MAC
    uint8_t arp_spa[4];  //sender IP
    uint8_t arp_tha[6];  //target MAC
    uint8_t arp_tpa[4];  //target IP
} __attribute__((packed)); 

/**
 * Analyse et affiche les champs de l'en-tête ARP.
 * @param packet    Pointeur vers le début de l'en-tête ARP.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @return          Taille de l'en-tête ARP (28 octets) ou 0 en cas d'erreur.
 */
int parse_arp(const u_char *packet, int length, int verbosity, int indent);

#endif /* ARP_H */