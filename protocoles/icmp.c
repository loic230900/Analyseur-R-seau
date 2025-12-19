/**
 * Ce module implémente le parsing des messages ICMP conformément à la RFC 792.
 * 
 */

#include "icmp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../util/safe_string.h"
#include "../util/textutils.h"

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

    if (verbosity == 2) {
        print_indent(indent);
        printf("ICMP: %s (type=%u, code=%u)\n", type_name, type, code);
    } else if (verbosity == 3) {
        print_indent(indent);
        printf("[L4] ICMP Header:\n");
        
        print_indent(indent);
        printf("      Type:     %u (%s)\n", type, type_name);
        
        print_indent(indent);
        printf("      Code:     %u\n", code);
        
        print_indent(indent);
        printf("      Checksum: 0x%04x\n", checksum);

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

/** Génère une chaîne de résumé détaillée pour ICMP en fonction du type et code.
 * Cette fonction factorise la logique de traduction type+code utilisée
 * dans les fonctions de résumé verbosité 1.
 * @param type        Type ICMP.
 * @param code        Code ICMP.
 * @param output      Buffer de sortie pour la chaîne résumée.
 * @param output_len  Taille du buffer de sortie.
 */
static void get_icmp_summary_string(uint8_t type, uint8_t code, char *output, size_t output_len) {
    switch(type) {
        case ICMP_ECHO:
            strncpy(output, "EchoReq", output_len);
            break;
        case ICMP_ECHOREPLY:
            strncpy(output, "EchoRep", output_len);
            break;
        case ICMP_DEST_UNREACH:
            switch(code) {
                case ICMP_NET_UNREACH:  strncpy(output, "Net Unreach", output_len); break;
                case ICMP_HOST_UNREACH: strncpy(output, "Host Unreach", output_len); break;
                case ICMP_PROT_UNREACH: strncpy(output, "Proto Unreach", output_len); break;
                case ICMP_PORT_UNREACH: strncpy(output, "Port Unreach", output_len); break;
                default: strncpy(output, "Dest Unreach", output_len); break;
            }
            break;
        case ICMP_TIME_EXCEEDED:
            strncpy(output, code == 0 ? "TTL Exceeded" : "Frag Timeout", output_len);
            break;
        case ICMP_REDIRECT:
            switch(code) {
                case 0: strncpy(output, "Redir Net", output_len); break;
                case 1: strncpy(output, "Redir Host", output_len); break;
                default: strncpy(output, "Redirect", output_len); break;
            }
            break;
        default:
            snprintf(output, output_len, "T%u", type);
            break;
    }
    output[output_len-1] = '\0';
}

/** Génère un résumé court ICMP pour verbosité 1 (sans IP destination).
 * Ajoute au buffer resume une description du type ICMP.
 * @param packet         Pointeur vers le début du paquet complet.
 * @param caplen         Longueur capturée totale.
 * @param offset_ip_start Offset du début de l'en-tête ICMP (après IP header).
 * @param resume         Buffer de sortie pour le résumé.
 * @return               1 en succès, 0 en échec.
 * 
 */
int icmp_v1_summary(const u_char *packet, int caplen, int offset_ip_start, char *resume) {
    if(caplen < offset_ip_start + ICMP_HDR_MIN_LEN) return 0;
    
    const struct icmphdr *icmp = (const struct icmphdr *)(packet + offset_ip_start);
    char type_str[32];
    get_icmp_summary_string(icmp->type, icmp->code, type_str, sizeof(type_str));
    
    char icmp_info[64];
    snprintf(icmp_info, sizeof(icmp_info), " | ICMP %s", type_str);
    safe_strcat(resume, icmp_info, RESUME_BUFFER_SIZE);
    
    return 1;
}

// Résumé verbosité 1 pour ICMP avec IP de destination

int icmp_v1_summary_with_ip(const u_char *packet, int caplen, int offset_icmp_start, char *resume, const char *dst_ip){
    if(caplen < offset_icmp_start + ICMP_HDR_MIN_LEN) return 0;
    
    const struct icmphdr *icmp = (const struct icmphdr *)(packet + offset_icmp_start);
    char type_str[32];
    get_icmp_summary_string(icmp->type, icmp->code, type_str, sizeof(type_str));
    
    char icmp_info[128];
    if(dst_ip && strlen(dst_ip) > 0) {
        snprintf(icmp_info, sizeof(icmp_info), " | ICMP %s -> %s", type_str, dst_ip);
    } else {
        snprintf(icmp_info, sizeof(icmp_info), " | ICMP %s", type_str);
    }
    
    safe_strcat(resume, icmp_info, RESUME_BUFFER_SIZE);
    return 1;
}
