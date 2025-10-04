#ifndef u_char
typedef unsigned char u_char;
#endif

#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

/**
 * Fonction de rappel pour traiter chaque paquet capturé.
 * @param args Arguments utilisateur (non utilisés ici).
 * @param header En-tête du paquet capturé.
 * @param packet Données du paquet capturé.
 * @return void
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
