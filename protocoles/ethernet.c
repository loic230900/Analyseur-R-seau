#include "ethernet.h"
#include <stdio.h>
#include <net/ethernet.h>

int parse_ethernet(const u_char *packet, int length, int verbosity, int indent, uint16_t *ethertype){
    if (length < 14) {
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un en-tête Ethernet.\n");
        return 0;
    }
    const struct ether_header *eth = (struct ether_header *)packet;
    *ethertype = ntohs(eth->ether_type);
 
    //formatage des adresses MAC pour affichage
    char src_mac[18], dst_mac[18];
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
             eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
             eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    
    //verbosite 2 ligne synthethique
    if(verbosity == 2){
        printf("Ethernet: src=%s dst=%s type=0x%04x\n", src_mac, dst_mac, *ethertype);
    }
    else if (verbosity == 3){
        //verbosite 3 detaillee
        printf("%*sEthernet Header:\n", indent, "");
        printf("%*s  Destination MAC: %s\n", indent, "", dst_mac);
        printf("%*s  Source MAC:      %s\n", indent, "", src_mac);
        printf("%*s  EtherType:      0x%04x\n", indent, "", *ethertype);
    }
}