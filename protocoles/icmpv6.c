#include "icmpv6.h"
#include "ndp.h"  // Pour déléguer les messages NDP
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

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
    if(length < (int)sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "Paquet trop court pour ICMPv6\n");
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

    // Sinon, traiter les messages ICMPv6 généraux
    if(verbosity == 2) {
        printf("ICMPv6: type=%u (%s), code=%u\n", type, type_name, code);
    }
    else if(verbosity == 3) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("ICMPv6:\n");
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Type:     %u (%s)\n", type, type_name);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Code:     %u\n", code);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Checksum: 0x%04x\n", checksum);

        // Parser spécifique selon le type
        switch(type) {
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY: {
                uint16_t id = ntohs(icmp6->icmp6_dataun.icmp6_un_data16[0]);
                uint16_t seq = ntohs(icmp6->icmp6_dataun.icmp6_un_data16[1]);
                for(int i = 0; i < indent+2; i++) printf(" ");
                printf("Identifier: %u, Sequence: %u\n", id, seq);
                break;
            }
            case ICMP6_DST_UNREACH:
            case ICMP6_TIME_EXCEEDED:
            case ICMP6_PARAM_PROB:
                // Afficher des détails sur l'erreur si nécessaire
                break;
        }
    }

    return sizeof(struct icmp6_hdr);
}