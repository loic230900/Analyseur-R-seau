/**
 * Analyseur de messages IGMP (Internet Group Management Protocol)
 * 
 * Ce module implémente le parsing des messages IGMP 
 */

#include "igmp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/igmp.h>
#include "../util/safe_string.h"
#include "../util/textutils.h"

/**
 * Retourne le nom du type IGMP
 * 
 * @param type Type IGMP
 * @return     Chaîne de caractères représentant le nom du type
 * 
 */
const char* get_igmp_type_name(uint8_t type) {
    switch(type) {
        case IGMP_MEMBERSHIP_QUERY:     return "Membership Query";
        case IGMP_V1_MEMBERSHIP_REPORT: return "v1 Membership Report";
        case IGMP_V2_MEMBERSHIP_REPORT: return "v2 Membership Report";
        case IGMP_V2_LEAVE_GROUP:       return "v2 Leave Group";
        case IGMP_V3_MEMBERSHIP_REPORT: return "v3 Membership Report";
        default:                        return "Unknown";
    }
}

/**
 * Retourne une description courte du type IGMP pour v1
 */
static const char* get_igmp_short_name(uint8_t type) {
    switch(type) {
        case IGMP_MEMBERSHIP_QUERY:     return "Query";
        case IGMP_V1_MEMBERSHIP_REPORT: return "v1 Report";
        case IGMP_V2_MEMBERSHIP_REPORT: return "v2 Report";
        case IGMP_V2_LEAVE_GROUP:       return "Leave";
        case IGMP_V3_MEMBERSHIP_REPORT: return "v3 Report";
        default:                        return NULL;
    }
}

// Parse et affiche un message IGMP (verbosités 2-3)

int parse_igmp(const u_char *packet, int length, int verbosity, int indent) {
    if (length < IGMP_HDR_LEN) {
        fprintf(stderr, "IGMP: Packet too short (need %d, got %d)\n", 
                IGMP_HDR_LEN, length);
        return 0;
    }

    const struct igmp *igmp = (const struct igmp *)packet;
    uint8_t type = igmp->igmp_type;
    uint8_t max_resp = igmp->igmp_code;  /* igmp_code = max response time in v2+ */
    uint16_t checksum = ntohs(igmp->igmp_cksum);
    
    /* Conversion de l'adresse de groupe */
    char group_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &igmp->igmp_group, group_addr, sizeof(group_addr));
    
    const char *type_name = get_igmp_type_name(type);

    if (verbosity == 2) {
        print_indent(indent);
        if (type == IGMP_MEMBERSHIP_QUERY) {
            /* Query : afficher si général ou spécifique */
            if (igmp->igmp_group.s_addr == 0) {
                printf("IGMP: General Query (max_resp=%u)\n", max_resp);
            } else {
                printf("IGMP: Group-Specific Query -> %s\n", group_addr);
            }
        } else if (type == IGMP_V3_MEMBERSHIP_REPORT) {
            printf("IGMP: %s\n", type_name);
        } else {
            printf("IGMP: %s -> %s\n", type_name, group_addr);
        }
    } 
    else if (verbosity == 3) {
        print_indent(indent);
        printf("[L4] IGMP Header:\n");
        
        print_indent(indent);
        printf("      Type:           %u (%s)\n", type, type_name);
        
        print_indent(indent);
        printf("      Max Resp Time:  %u", max_resp);
        if (max_resp > 0) {
            /* IGMPv2+ : temps en 1/10 de seconde */
            printf(" (%.1f sec)", max_resp / 10.0);
        }
        printf("\n");
        
        print_indent(indent);
        printf("      Checksum:       0x%04x\n", checksum);
        
        print_indent(indent);
        if (igmp->igmp_group.s_addr == 0) {
            printf("      Group Address:  0.0.0.0 (General Query)\n");
        } else {
            printf("      Group Address:  %s\n", group_addr);
        }
        
        /* Pour IGMPv3 Reports, indiquer qu'il y a des Group Records */
        if (type == IGMP_V3_MEMBERSHIP_REPORT && length > IGMP_HDR_LEN) {
            print_indent(indent);
            printf("      [IGMPv3 Report with Group Records - %d bytes payload]\n", 
                   length - IGMP_HDR_LEN);
        }
    }

    return IGMP_HDR_LEN;
}

/**
 * Verbosité 1: génère un résumé IGMP concis
 */
int igmp_v1_summary(const u_char *packet, int caplen, int offset_igmp, 
                    char *resume, const char *dst_ip) {
    if (caplen < offset_igmp + IGMP_HDR_LEN) {
        safe_strcat(resume, " | IGMP (truncated)", RESUME_BUFFER_SIZE);
        return 0;
    }
    
    const struct igmp *igmp = (const struct igmp *)(packet + offset_igmp);
    uint8_t type = igmp->igmp_type;
    
    safe_strcat(resume, " | IGMP", RESUME_BUFFER_SIZE);
    
    /* Ajouter le nom court du type */
    const char *short_name = get_igmp_short_name(type);
    if (short_name) {
        safe_strcat(resume, " ", RESUME_BUFFER_SIZE);
        safe_strcat(resume, short_name, RESUME_BUFFER_SIZE);
    }
    
    /* Ajouter l'adresse de groupe pour les Reports/Leave */
    if (type != IGMP_MEMBERSHIP_QUERY || igmp->igmp_group.s_addr != 0) {
        char group_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &igmp->igmp_group, group_addr, sizeof(group_addr));
        
        safe_strcat(resume, " -> ", RESUME_BUFFER_SIZE);
        safe_strcat(resume, group_addr, RESUME_BUFFER_SIZE);
    } else if (dst_ip) {
        /* General Query : afficher la destination multicast */
        safe_strcat(resume, " -> ", RESUME_BUFFER_SIZE);
        safe_strcat(resume, dst_ip, RESUME_BUFFER_SIZE);
    }
    
    return 1;
}
