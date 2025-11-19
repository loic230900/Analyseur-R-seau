#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>  // Fournit struct ether_arp système

//Types Ethernet
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

// struct ether_arp est maintenant fournie par <netinet/if_ether.h>
// Elle contient déjà : ea_hdr, arp_sha, arp_spa, arp_tha, arp_tpa 

/**
 * Analyse et affiche les champs de l'en-tête ARP.
 * @param packet    Pointeur vers le début de l'en-tête ARP.
 * @param length    Longueur restante du paquet.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espaces pour l'affichage.
 * @return          Taille de l'en-tête ARP (28 octets) ou 0 en cas d'erreur.
 */
int parse_arp(const u_char *packet, int length, int verbosity, int indent);

/* Verbosité 1: ajoute who-has / is-at dans resume. offset_after_eth = position de l'en-tête ARP */
int arp_v1_summary(const u_char *packet, int caplen, int offset_after_eth, char *resume);

#endif /* ARP_H */