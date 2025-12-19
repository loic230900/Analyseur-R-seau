/**
 * @file udp.c
 * @brief Analyseur de datagrammes UDP (couche 4 - Transport)
 * 
 * Ce module implémente le parsing des datagrammes UDP conformément à la RFC 768.
 * UDP (User Datagram Protocol) fournit un service de transport sans connexion,
 * non fiable mais rapide et léger.
 * 
 * Protocole IP : 17
 * 
 * Structure de l'en-tête UDP (8 octets fixes) :
 * - Port source (16 bits)
 * - Port destination (16 bits)
 * - Longueur (16 bits) : taille totale du datagramme (en-tête + données)
 * - Checksum (16 bits) : optionnel en IPv4, obligatoire en IPv6
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "udp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include "../util/safe_string.h"
#include "../util/textutils.h"

/* ============================================================================
 * FONCTION DE PARSING PRINCIPALE (VERBOSITÉ 2-3)
 * ============================================================================ */

/**
 * @brief Parse et affiche un en-tête UDP
 * @param packet Pointeur vers le début de l'en-tête UDP
 * @param length Longueur restante du paquet
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent Indentation pour l'affichage
 * @param src_port Pointeur de sortie pour le port source
 * @param dst_port Pointeur de sortie pour le port destination
 * @return Taille de l'en-tête UDP (8 octets) ou 0 si erreur
 */
int parse_udp(const u_char *packet, int length, int verbosity, int indent,
              uint16_t *src_port, uint16_t *dst_port) {
    if (length < UDP_HDR_LEN) {
        fprintf(stderr, "UDP: Packet too short (need %d, got %d)\n",
                UDP_HDR_LEN, length);
        return 0;
    }

    const struct udphdr *udp = (const struct udphdr *)packet;
    
    /* Extraction des champs de l'en-tête */
    *src_port = ntohs(udp->source);
    *dst_port = ntohs(udp->dest);
    uint16_t udp_len = ntohs(udp->len);
    uint16_t checksum = ntohs(udp->check);
    
    /* Calcul de la taille du payload */
    int payload_len = udp_len - UDP_HDR_LEN;
    if (payload_len < 0) payload_len = 0;

    /* Verbosité 2 : affichage synthétique */
    if (verbosity == 2) {
        print_indent(indent);
        printf("UDP: %u -> %u, len=%u\n", *src_port, *dst_port, udp_len);
    }
    /* Verbosité 3 : affichage détaillé */
    else if (verbosity == 3) {
        print_indent(indent);
        printf("[L4] UDP Header:\n");
        
        print_indent(indent);
        printf("      Source Port:      %u\n", *src_port);
        
        print_indent(indent);
        printf("      Dest Port:        %u\n", *dst_port);
        
        print_indent(indent);
        printf("      Length:           %u bytes (payload: %d)\n", udp_len, payload_len);
        
        print_indent(indent);
        printf("      Checksum:         0x%04x\n", checksum);
    }

    return UDP_HDR_LEN;
}

/* ============================================================================
 * FONCTION DE RÉSUMÉ (VERBOSITÉ 1)
 * ============================================================================ */

/**
 * @brief Génère un résumé des ports UDP pour la verbosité 1
 * @param packet Paquet complet
 * @param caplen Longueur capturée
 * @param offset_transport Offset vers l'en-tête UDP
 * @param resume Buffer de sortie pour le résumé
 * @return 1 si succès, 0 si erreur
 */
int udp_v1_ports_summary(const u_char *packet, int caplen, int offset_transport, char *resume) {
    if(caplen < offset_transport + (int)sizeof(struct udphdr)) return 0;
    const struct udphdr *udp = (const struct udphdr *)(packet + offset_transport);
    uint16_t sp = ntohs(udp->source), dp = ntohs(udp->dest);
    
    /* Identifier les ports UDP connus non parsés explicitement */
    const char *service = NULL;
    if(sp == 20 || dp == 20) service = "FTP-Data";
    else if(sp == 1900 || dp == 1900) service = "SSDP";
    else if(sp == 5353 || dp == 5353) service = "mDNS";
    else if(sp == 123 || dp == 123) service = "NTP";
    else if(sp == 137 || dp == 137) service = "NetBIOS-NS";
    else if(sp == 138 || dp == 138) service = "NetBIOS-DGM";
    else if(sp == 161 || dp == 161) service = "SNMP";
    else if(sp == 162 || dp == 162) service = "SNMP-Trap";
    
    char tmp[64];
    if(service) {
        snprintf(tmp, sizeof(tmp), " | UDP %u>%u (%s)", sp, dp, service);
    } else {
        snprintf(tmp, sizeof(tmp), " | UDP %u>%u", sp, dp);
    }
    safe_strcat(resume, tmp, RESUME_BUFFER_SIZE);
    return 1;
}
