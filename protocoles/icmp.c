/**
 * @file icmp.c
 * @brief Analyseur de messages ICMP (couche 3.5 - Contrôle)
 * 
 * Ce module implémente le parsing des messages ICMP conformément à la RFC 792.
 * ICMP (Internet Control Message Protocol) est utilisé pour les diagnostics
 * réseau (ping, traceroute) et la signalisation d'erreurs.
 * 
 * Protocole IP : 1
 * 
 * Types ICMP principaux :
 * - Type 0 : Echo Reply (réponse ping)
 * - Type 3 : Destination Unreachable (avec codes pour Net/Host/Port/Proto)
 * - Type 5 : Redirect
 * - Type 8 : Echo Request (requête ping)
 * - Type 11 : Time Exceeded (TTL expiré - traceroute)
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "icmp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../util/safe_string.h"
#include "../util/textutils.h"

/* ============================================================================
 * FONCTION UTILITAIRE - NOM DU TYPE ICMP
 * ============================================================================ */

/**
 * @brief Retourne le nom lisible d'un type ICMP
 * @param type Code du type ICMP
 * @return Chaîne de caractères représentant le type
 */
const char* get_icmp_type_name(uint8_t type) {
    switch(type) {
        case ICMP_ECHOREPLY:     return "Echo Reply";
        case ICMP_DEST_UNREACH:  return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH: return "Source Quench";
        case ICMP_REDIRECT:      return "Redirect";
        case ICMP_ECHO:          return "Echo Request";
        case ICMP_TIME_EXCEEDED: return "Time Exceeded";
        case ICMP_PARAMETERPROB: return "Parameter Problem";
        case ICMP_TIMESTAMP:     return "Timestamp Request";
        case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
        case ICMP_INFO_REQUEST:  return "Information Request";
        case ICMP_INFO_REPLY:    return "Information Reply";
        case ICMP_ADDRESS:       return "Address Mask Request";
        case ICMP_ADDRESSREPLY:  return "Address Mask Reply";
        default:                 return "Unknown";
    }
}

/* ============================================================================
 * FONCTION DE PARSING PRINCIPALE (VERBOSITÉ 2-3)
 * ============================================================================ */

/**
 * @brief Parse et affiche un en-tête ICMP
 * @param packet Pointeur vers le début de l'en-tête ICMP
 * @param length Longueur restante du paquet
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent Indentation pour l'affichage
 * @return Taille de l'en-tête ICMP (8 octets minimum) ou 0 si erreur
 */
int parse_icmp(const u_char *packet, int length, int verbosity, int indent) {
    if (length < ICMP_HDR_MIN_LEN) {
        fprintf(stderr, "ICMP: Packet too short (need %d, got %d)\n", 
                ICMP_HDR_MIN_LEN, length);
        return 0;
    }

    const struct icmphdr *icmp = (const struct icmphdr *)packet;
    uint8_t type = icmp->type;
    uint8_t code = icmp->code;
    uint16_t checksum = ntohs(icmp->checksum);
    const char *type_name = get_icmp_type_name(type);

    /* Verbosité 2 : affichage synthétique sur une ligne */
    if (verbosity == 2) {
        print_indent(indent);
        printf("ICMP: %s (type=%u, code=%u)\n", type_name, type, code);
    }
    /* Verbosité 3 : affichage détaillé avec indicateur de couche OSI */
    else if (verbosity == 3) {
        print_indent(indent);
        printf("[L4] ICMP Header:\n");
        
        print_indent(indent);
        printf("      Type:     %u (%s)\n", type, type_name);
        
        print_indent(indent);
        printf("      Code:     %u\n", code);
        
        print_indent(indent);
        printf("      Checksum: 0x%04x\n", checksum);

        /* Données spécifiques pour Echo Request/Reply */
        switch(type) {
            case ICMP_ECHO:
            case ICMP_ECHOREPLY: {
                uint16_t id = ntohs(icmp->un.echo.id);
                uint16_t seq = ntohs(icmp->un.echo.sequence);
                
                print_indent(indent);
                printf("      Identifier: %u, Sequence: %u\n", id, seq);
                break;
            }
            default:
                break;
        }
    }

    return ICMP_HDR_MIN_LEN;
}

/* ============================================================================
 * FONCTIONS DE RÉSUMÉ (VERBOSITÉ 1)
 * ============================================================================ */

/**
 * @brief Génère un résumé ICMP pour la verbosité 1
 * @param packet Pointeur vers le début du paquet
 * @param caplen Longueur capturée
 * @param offset_ip_start Offset de l'en-tête ICMP dans le paquet
 * @param resume Buffer de résumé à remplir
 * @return 1 si succès, 0 si erreur
 */
int icmp_v1_summary(const u_char *packet, int caplen, int offset_ip_start, char *resume) {
    if(caplen < offset_ip_start + ICMP_HDR_MIN_LEN) return 0;
    const struct icmphdr *icmp = (const struct icmphdr *)(packet + offset_ip_start);
    switch(icmp->type){
        case ICMP_ECHO: safe_strcat(resume, " EchoReq", RESUME_BUFFER_SIZE); break;
        case ICMP_ECHOREPLY: safe_strcat(resume, " EchoRep", RESUME_BUFFER_SIZE); break;
        case ICMP_DEST_UNREACH: safe_strcat(resume, " Unreach", RESUME_BUFFER_SIZE); break;
        case ICMP_TIME_EXCEEDED: safe_strcat(resume, " TimeEx", RESUME_BUFFER_SIZE); break;
        case ICMP_REDIRECT: safe_strcat(resume, " Redirect", RESUME_BUFFER_SIZE); break;
        default: {
            char tmp[16]; 
            snprintf(tmp, sizeof(tmp), " T%u", icmp->type);
            safe_strcat(resume, tmp, RESUME_BUFFER_SIZE);
        }
    }
    return 1;
}

/**
 * @brief Génère un résumé ICMP avec adresse IP de destination
 * @param packet Pointeur vers le début du paquet
 * @param caplen Longueur capturée
 * @param offset_icmp_start Offset de l'en-tête ICMP
 * @param resume Buffer de résumé à remplir
 * @param dst_ip Adresse IP de destination formatée
 * @return 1 si succès, 0 si erreur
 */
int icmp_v1_summary_with_ip(const u_char *packet, int caplen, int offset_icmp_start, char *resume, const char *dst_ip){
    if(caplen < offset_icmp_start + 8) return 0;
    const struct icmphdr *icmp = (const struct icmphdr *)(packet + offset_icmp_start);
    char type_str[64] = "";
    switch(icmp->type){
        case ICMP_ECHO: strcpy(type_str, "EchoReq"); break;
        case ICMP_ECHOREPLY: strcpy(type_str, "EchoRep"); break;
        case ICMP_DEST_UNREACH:
            switch(icmp->code) {
                case ICMP_NET_UNREACH: strcpy(type_str, "Net Unreach"); break;
                case ICMP_HOST_UNREACH: strcpy(type_str, "Host Unreach"); break;
                case ICMP_PROT_UNREACH: strcpy(type_str, "Proto Unreach"); break;
                case ICMP_PORT_UNREACH: strcpy(type_str, "Port Unreach"); break;
                default: strcpy(type_str, "Dest Unreach"); break;
            }
            break;
        case ICMP_TIME_EXCEEDED:
            strcpy(type_str, icmp->code == 0 ? "TTL Exceeded" : "Frag Timeout");
            break;
        case ICMP_REDIRECT:
            switch(icmp->code) {
                case 0: strcpy(type_str, "Redir Net"); break;
                case 1: strcpy(type_str, "Redir Host"); break;
                default: strcpy(type_str, "Redirect"); break;
            }
            break;
        default: {
            snprintf(type_str, sizeof(type_str), "T%u", icmp->type);
        }
    }
    
    char icmp_info[128];
    if(dst_ip && strlen(dst_ip) > 0) {
        snprintf(icmp_info, sizeof(icmp_info), " | ICMP %s -> %s", type_str, dst_ip);
    } else {
        snprintf(icmp_info, sizeof(icmp_info), " | ICMP %s", type_str);
    }
    
    safe_strcat(resume, icmp_info, RESUME_BUFFER_SIZE);
    return 1;
}
