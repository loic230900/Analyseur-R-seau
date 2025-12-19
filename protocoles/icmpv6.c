/**
 * Ce module implémente le parsing des messages ICMPv6 conformément à la RFC 4443.
 * Gère les messages d'erreur, de contrôle et délègue les messages NDP (types 133-137).
 */

#include "icmpv6.h"
#include "ndp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../util/textutils.h"
#include "../util/safe_string.h"

const char* get_icmpv6_type_name(uint8_t type) {
    switch(type) {
        case ICMP6_DST_UNREACH: return "Destination Unreachable";
        case ICMP6_PACKET_TOO_BIG: return "Packet Too Big";
        case ICMP6_TIME_EXCEEDED: return "Time Exceeded";
        case ICMP6_PARAM_PROB: return "Parameter Problem";
        case ICMP6_ECHO_REQUEST: return "Echo Request";
        case ICMP6_ECHO_REPLY: return "Echo Reply";
        case ND_ROUTER_SOLICIT: return "Router Solicitation (NDP)";
        case ND_ROUTER_ADVERT: return "Router Advertisement (NDP)";
        case ND_NEIGHBOR_SOLICIT: return "Neighbor Solicitation (NDP)";
        case ND_NEIGHBOR_ADVERT: return "Neighbor Advertisement (NDP)";
        case ND_REDIRECT: return "Redirect (NDP)";
        /* MLD - Multicast Listener Discovery */
        case MLD_LISTENER_QUERY: return "MLD Query";
        case MLD_LISTENER_REPORT: return "MLDv1 Report";
        case MLD_LISTENER_REDUCTION: return "MLDv1 Done";
        case MLD2_LISTENER_REPORT: return "MLDv2 Report";
        default: return "Unknown";
    }
}

/** Génère une chaîne de résumé détaillée pour ICMPv6 en fonction du type et code.
 * Cette fonction factorise la logique de traduction type+code utilisée
 * dans toutes les fonctions de parsing et résumé.
 * @param type        Type ICMPv6.
 * @param code        Code ICMPv6.
 * @param output      Buffer de sortie pour la chaîne résumée.
 * @param output_len  Taille du buffer de sortie.
 * 
 */
static void get_icmpv6_summary_string(uint8_t type, uint8_t code, char *output, size_t output_len) {
    switch(type) {
        // Messages NDP
        case ND_ROUTER_SOLICIT:
            strncpy(output, "RS", output_len);
            break;
        case ND_ROUTER_ADVERT:
            strncpy(output, "RA", output_len);
            break;
        case ND_NEIGHBOR_SOLICIT:
            strncpy(output, "NS", output_len);
            break;
        case ND_NEIGHBOR_ADVERT:
            strncpy(output, "NA", output_len);
            break;
        case ND_REDIRECT:
            strncpy(output, "Redirect", output_len);
            break;
        // Echo
        case ICMP6_ECHO_REQUEST:
            strncpy(output, "EchoReq", output_len);
            break;
        case ICMP6_ECHO_REPLY:
            strncpy(output, "EchoRep", output_len);
            break;
        // Time Exceeded
        case ICMP6_TIME_EXCEEDED:
            strncpy(output, code == 0 ? "TTL Exceeded" : "Frag Timeout", output_len);
            break;
        // Destination Unreachable
        case ICMP6_DST_UNREACH:
            switch(code) {
                case 0: strncpy(output, "No Route", output_len); break;
                case 1: strncpy(output, "Admin Prohib", output_len); break;
                case 3: strncpy(output, "Addr Unreach", output_len); break;
                case 4: strncpy(output, "Port Unreach", output_len); break;
                default: strncpy(output, "Dest Unreach", output_len); break;
            }
            break;
        // Packet Too Big
        case ICMP6_PACKET_TOO_BIG:
            strncpy(output, "Pkt Too Big", output_len);
            break;
        // Parameter Problem
        case ICMP6_PARAM_PROB:
            strncpy(output, "Param Prob", output_len);
            break;
        // MLD - Multicast Listener Discovery
        case MLD_LISTENER_QUERY:
            strncpy(output, "MLD Query", output_len);
            break;
        case MLD_LISTENER_REPORT:
            strncpy(output, "MLDv1 Report", output_len);
            break;
        case MLD_LISTENER_REDUCTION:
            strncpy(output, "MLDv1 Done", output_len);
            break;
        case MLD2_LISTENER_REPORT:
            strncpy(output, "MLDv2 Report", output_len);
            break;
        default:
            snprintf(output, output_len, "T%u", type);
            break;
    }
    output[output_len-1] = '\0';
}

// Parse et affiche un en-tête ICMPv6

int parse_icmpv6(const u_char *packet, int length, int verbosity, int indent) {
    if (length < (int)sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "ICMPv6: Packet too short for ICMPv6 header (need %zu, got %d)\n",
                sizeof(struct icmp6_hdr), length);
        return 0;
    }
    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)packet;
    uint8_t type = icmp6->icmp6_type;
    uint8_t code = icmp6->icmp6_code;
    uint16_t checksum = ntohs(icmp6->icmp6_cksum);
    const char *type_name = get_icmpv6_type_name(type);

    // Si c'est un message NDP (types 133-137), déléguer à ndp
    if(type >= ND_ROUTER_SOLICIT && type <= ND_REDIRECT) {
        return parse_ndp(packet, length, verbosity, indent);
    }

    if(verbosity == 2) {
        char type_str[64];
        get_icmpv6_summary_string(type, code, type_str, sizeof(type_str));
        print_indent(indent);
        printf("ICMPv6: %s\n", type_str);
    }
    else if(verbosity == 3) {
        print_indent(indent);
        printf("[L4] ICMPv6 Header:\n");
        
        print_indent(indent);
        printf("      Type:     %u (%s)\n", type, type_name);
        
        print_indent(indent);
        printf("      Code:     %u\n", code);
        
        print_indent(indent);
        printf("      Checksum: 0x%04x\n", checksum);

        switch(type) {
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY: {
                uint16_t id = ntohs(icmp6->icmp6_dataun.icmp6_un_data16[0]);
                uint16_t seq = ntohs(icmp6->icmp6_dataun.icmp6_un_data16[1]);
                print_indent(indent);
                printf("      ID: %u, Sequence: %u\n", id, seq);
                break;
            }
            default:
                break;
        }
    }

    return sizeof(struct icmp6_hdr);
}

// Résumé verbosité 1 pour ICMPv6 avec infos pertinentes selon le type

int icmpv6_v1_summary(const u_char *packet, int caplen, int offset_icmp6, char *resume, const char *dst_ip){
    if(caplen < offset_icmp6 + (int)sizeof(struct icmp6_hdr)) return 0;
    
    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)(packet + offset_icmp6);
    uint8_t type = icmp6->icmp6_type;
    char type_str[64];
    get_icmpv6_summary_string(type, icmp6->icmp6_code, type_str, sizeof(type_str));
    
    char icmpv6_info[160];
    
    /* Pour NS/NA : afficher l'adresse cible (target) */
    if((type == ND_NEIGHBOR_SOLICIT || type == ND_NEIGHBOR_ADVERT) &&
       caplen >= offset_icmp6 + 24) { /* 8 bytes header + 16 bytes target */
        char target[INET6_ADDRSTRLEN];
        const struct in6_addr *target_addr = (const struct in6_addr *)(packet + offset_icmp6 + 8);
        inet_ntop(AF_INET6, target_addr, target, sizeof(target));
        snprintf(icmpv6_info, sizeof(icmpv6_info), " | ICMPv6 %s %s", type_str, target);
    }
    /* Pour RS/RA : afficher juste le type */
    else if(type == ND_ROUTER_SOLICIT || type == ND_ROUTER_ADVERT) {
        snprintf(icmpv6_info, sizeof(icmpv6_info), " | ICMPv6 %s", type_str);
    }
    /* Pour Echo : afficher la destination */
    else if((type == ICMP6_ECHO_REQUEST || type == ICMP6_ECHO_REPLY) && dst_ip && *dst_ip) {
        snprintf(icmpv6_info, sizeof(icmpv6_info), " | ICMPv6 %s -> %s", type_str, dst_ip);
    }
    /* Autres types */
    else {
        snprintf(icmpv6_info, sizeof(icmpv6_info), " | ICMPv6 %s", type_str);
    }
    
    safe_strcat(resume, icmpv6_info, RESUME_BUFFER_SIZE);
    return 1;
}