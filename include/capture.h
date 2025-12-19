/**
 * Ce module définit les structures et fonctions pour la capture
 * et le traitement des paquets réseau via libpcap.
 * 
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <stdint.h>

/*
 * u_char est utilisé dans tout le projet pour représenter les octets bruts
 * des paquets réseau. Cette définition assure la portabilité.
 */
#ifndef UCHAR_TYPEDEF_GUARD
#define UCHAR_TYPEDEF_GUARD
typedef unsigned char u_char;
#endif

/**
 *  Structure pour passer des arguments à la fonction de rappel pcap
 * 
 * Cette structure est transmise à packet_handler() via le paramètre user de
 * pcap_loop(). Elle permet de passer le niveau de verbosité souhaité.
 */
typedef struct {
    int verbosity;  // Niveau de verbosité : 1=concis, 2=synthétique, 3=complet 
} capture_args_t;

/**
 * Cette fonction est appelée par pcap_loop() pour chaque paquet reçu.
 * Elle analyse le paquet couche par couche et 
 * affiche les informations selon le niveau de verbosité demandé.
 * 
 * Flux de traitement :
 * 1. Analyse de l'en-tête Ethernet (EtherType)
 * 2. Routage vers IPv4, IPv6, ARP ou RARP selon l'EtherType
 * 3. Pour IP : analyse de la couche transport 
 * 4. Pour TCP/UDP : détection et analyse du protocole applicatif
 * 
 * @param args     Arguments utilisateur (pointeur vers capture_args_t casté en u_char*)
 * @param header   En-tête du paquet capturé (timestamps, longueurs)
 * @param packet   Données brutes du paquet capturé
 * 
 * @note Le paramètre args contient le niveau de verbosité (1, 2 ou 3)
 * @note header->caplen peut être < header->len si le paquet est tronqué
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif /* CAPTURE_H */
