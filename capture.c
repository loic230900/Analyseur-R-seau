#include <pcap.h>
#include <stdio.h>
#include "capture.h"
#include "hexdump.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // paramètre non utilisé
    static int packet_count = 0;
    packet_count++;
    printf("\nPaquet %d - %d octets capturés\n", packet_count, header->len);

    // Appel de la fonction d'affichage hexdump pour les données du paquet
    print_hexdump(packet, header->len);

    //  Ethernet/IP/TCP en fonction du niveau de verbosité.)
}
