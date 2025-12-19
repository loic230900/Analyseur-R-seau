/**
 * @file icmpv6.c
 * @brief Analyseur de messages ICMPv6 (couche 3.5 - Contrôle)
 * 
 * Ce module implémente le parsing des messages ICMPv6 conformément aux RFCs :
 * - RFC 4443 : ICMPv6 (Internet Control Message Protocol for IPv6)
 * - RFC 4861 : NDP (Neighbor Discovery Protocol) - types 133-137
 * 
 * ICMPv6 remplit des fonctions essentielles en IPv6 :
 * - Signalisation d'erreurs (Destination Unreachable, Packet Too Big, etc.)
 * - Diagnostic (Echo Request/Reply = ping6)
 * - Découverte du voisinage (NDP) - délégué à ndp.c
 * 
 * Next Header IPv6 : 58
 * 
 * Types ICMPv6 :
 * - Erreurs (0-127) :
 *   - 1 : Destination Unreachable
 *   - 2 : Packet Too Big (MTU Path Discovery)
 *   - 3 : Time Exceeded
 *   - 4 : Parameter Problem
 * - Informational (128-255) :
 *   - 128 : Echo Request (ping6)
 *   - 129 : Echo Reply
 *   - 133-137 : NDP (Router/Neighbor Solicitation/Advertisement, Redirect)
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "icmpv6.h"
#include "ndp.h"  /* Pour déléguer les messages NDP */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../util/textutils.h"
#include "../util/safe_string.h"

// Fonction pour récupérer le nom du type ICMPv6
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
        default: return "Unknown";
    }
}

// Parsing de l'en-tête ICMPv6
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

    /* Sinon, traiter les messages ICMPv6 généraux */
    if(verbosity == 2) {
        print_indent(indent);
        
        /* Affichage avec code détaillé pour les types communs */
        if(type == ICMP6_DST_UNREACH) {
            const char *code_str = "Unknown";
            switch(code) {
                case 0: code_str = "No Route"; break;
                case 1: code_str = "Admin Prohibited"; break;
                case 3: code_str = "Address Unreachable"; break;
                case 4: code_str = "Port Unreachable"; break;
            }
            printf("ICMPv6: Dest Unreach (%s)\n", code_str);
        } else if(type == ICMP6_TIME_EXCEEDED) {
            printf("ICMPv6: %s\n", code == 0 ? "TTL Exceeded" : "Fragment Timeout");
        } else {
            printf("ICMPv6: %s (type=%u, code=%u)\n", type_name, type, code);
        }
    }
    else if(verbosity == 3) {
        print_indent(indent);
        printf("[L4] ICMPv6 Header:\n");
        
        print_indent(indent);
        printf("      Type:     %u (%s)\n", type, type_name);
        
        print_indent(indent);
        printf("      Code:     %u", code);
        
        /* Ajouter description du code pour les types courants */
        if(type == ICMP6_DST_UNREACH) {
            switch(code) {
                case 0: printf(" (No Route to Destination)"); break;
                case 1: printf(" (Communication Administratively Prohibited)"); break;
                case 3: printf(" (Address Unreachable)"); break;
                case 4: printf(" (Port Unreachable)"); break;
            }
        } else if(type == ICMP6_TIME_EXCEEDED) {
            printf(" (%s)", code == 0 ? "Hop Limit Exceeded" : "Fragment Reassembly Time Exceeded");
        } else if(type == ICMP6_PARAM_PROB) {
            switch(code) {
                case 0: printf(" (Erroneous Header Field)"); break;
                case 1: printf(" (Unrecognized Next Header)"); break;
                case 2: printf(" (Unrecognized IPv6 Option)"); break;
            }
        }
        printf("\n");
        
        print_indent(indent);
        printf("      Checksum: 0x%04x\n", checksum);

        /* Parser spécifique selon le type */
        switch(type) {
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY: {
                uint16_t id = ntohs(icmp6->icmp6_dataun.icmp6_un_data16[0]);
                uint16_t seq = ntohs(icmp6->icmp6_dataun.icmp6_un_data16[1]);
                print_indent(indent);
                printf("      ID: %u, Sequence: %u\n", id, seq);
                break;
            }
            case ICMP6_DST_UNREACH:
            case ICMP6_TIME_EXCEEDED:
            case ICMP6_PARAM_PROB:
                break;
        }
    }

    return sizeof(struct icmp6_hdr);
}

int icmpv6_v1_summary(const u_char *packet, int caplen, int offset_ip6_start, char *resume, const char *dst_ip){
    if(caplen < offset_ip6_start + (int)sizeof(struct icmp6_hdr)) return 0;
    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)(packet + offset_ip6_start);
    uint8_t t = icmp6->icmp6_type;
    uint8_t c = icmp6->icmp6_code;
    
    // Ajouter le préfixe ICMPv6
    safe_strcat(resume, " | ICMPv6 ", RESUME_BUFFER_SIZE);
    
    // NDP messages
    if(t == ND_ROUTER_SOLICIT) safe_strcat(resume, "RS", RESUME_BUFFER_SIZE);
    else if(t == ND_ROUTER_ADVERT) safe_strcat(resume, "RA", RESUME_BUFFER_SIZE);
    else if(t == ND_NEIGHBOR_SOLICIT) safe_strcat(resume, "NS", RESUME_BUFFER_SIZE);
    else if(t == ND_NEIGHBOR_ADVERT) safe_strcat(resume, "NA", RESUME_BUFFER_SIZE);
    else if(t == ND_REDIRECT) safe_strcat(resume, "Redirect", RESUME_BUFFER_SIZE);
    // ICMPv6 standard messages
    else if(t == ICMP6_ECHO_REQUEST) safe_strcat(resume, "EchoReq", RESUME_BUFFER_SIZE);
    else if(t == ICMP6_ECHO_REPLY) safe_strcat(resume, "EchoRep", RESUME_BUFFER_SIZE);
    else if(t == ICMP6_TIME_EXCEEDED) {
        safe_strcat(resume, c == 0 ? "TTL Exceeded" : "Frag Timeout", RESUME_BUFFER_SIZE);
    }
    else if(t == ICMP6_DST_UNREACH) {
        switch(c) {
            case 0: safe_strcat(resume, "No Route", RESUME_BUFFER_SIZE); break;
            case 1: safe_strcat(resume, "Admin Prohib", RESUME_BUFFER_SIZE); break;
            case 3: safe_strcat(resume, "Addr Unreach", RESUME_BUFFER_SIZE); break;
            case 4: safe_strcat(resume, "Port Unreach", RESUME_BUFFER_SIZE); break;
            default: safe_strcat(resume, "Dest Unreach", RESUME_BUFFER_SIZE); break;
        }
    }
    else if(t == ICMP6_PACKET_TOO_BIG) safe_strcat(resume, "Pkt Too Big", RESUME_BUFFER_SIZE);
    else if(t == ICMP6_PARAM_PROB) safe_strcat(resume, "Param Prob", RESUME_BUFFER_SIZE);
    else {
        char buf[16]; 
        snprintf(buf, sizeof(buf), "T%u", t); 
        safe_strcat(resume, buf, RESUME_BUFFER_SIZE);
    }
    
    // Ajouter l'IP destination pour Echo Request/Reply (comme ICMP)
    if((t == ICMP6_ECHO_REQUEST || t == ICMP6_ECHO_REPLY) && dst_ip && strlen(dst_ip) > 0) {
        char ip_info[128];
        snprintf(ip_info, sizeof(ip_info), " -> %s", dst_ip);
        safe_strcat(resume, ip_info, RESUME_BUFFER_SIZE);
    }
    
    return 1;
}