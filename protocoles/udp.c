/**
 *  Analyseur de datagrammes UDP 
 * 
 * Ce module implémente le parsing des datagrammes UDP conformément à la RFC 768
 * 
 */

#include "udp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include "../util/safe_string.h"
#include "../util/textutils.h"

// parse UDP pour verbosités 2 et 3

int parse_udp(const u_char *packet, int length, int verbosity, int indent, uint16_t *src_port, uint16_t *dst_port) {

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

/**
 * @brief Génère un résumé des ports UDP pour la verbosité 1
 * @param packet Paquet complet
 * @param caplen Longueur capturée
 * @param offset_transport Offset vers l'en-tête UDP
 * @param resume Buffer de sortie pour le résumé
 * @param src_ip Adresse IP source (chaîne de caractères)
 * @param dst_ip Adresse IP destination (chaîne de caractères)
 * @return 1 si succès, 0 si erreur
 */
int udp_v1_ports_summary(const u_char *packet, int caplen, int offset_transport, 
                         char *resume, const char *src_ip, const char *dst_ip) {
    if(caplen < offset_transport + (int)sizeof(struct udphdr)) return 0;
    const struct udphdr *udp = (const struct udphdr *)(packet + offset_transport);
    uint16_t sp = ntohs(udp->source), dp = ntohs(udp->dest);
    
    /* Identifier les ports UDP connus non parsés explicitement */
    /* Note: mDNS (5353) est parsé via DNS, FTP-Data (20) est TCP pas UDP */
    const char *service = NULL;
    if(sp == 1900 || dp == 1900) service = "SSDP";
    else if(sp == 123 || dp == 123) service = "NTP";
    else if(sp == 137 || dp == 137) service = "NetBIOS-NS";
    else if(sp == 138 || dp == 138) service = "NetBIOS-DGM";
    else if(sp == 161 || dp == 161) service = "SNMP";
    else if(sp == 162 || dp == 162) service = "SNMP-Trap";
    
    char tmp[128];
    if(service) {
        snprintf(tmp, sizeof(tmp), " | UDP %s[%u] -> %s[%u] (%s)", src_ip, sp, dst_ip, dp, service);
    } else {
        snprintf(tmp, sizeof(tmp), " | UDP %s[%u] -> %s[%u]", src_ip, sp, dst_ip, dp);
    }
    safe_strcat(resume, tmp, RESUME_BUFFER_SIZE);
    return 1;
}
