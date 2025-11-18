#include "icmp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

//fonction pour obtenir le nom du type ICMP
const char* get_icmp_type_name(uint8_t type) {
    switch(type) {
        case ICMP_ECHOREPLY:      return "Echo Reply (ping)";
        case ICMP_DEST_UNREACH:   return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH:  return "Source Quench";
        case ICMP_REDIRECT:       return "Redirect";
        case ICMP_ECHO:           return "Echo Request (ping)";
        case ICMP_TIME_EXCEEDED:  return "Time Exceeded";
        case ICMP_PARAMETERPROB:  return "Parameter Problem";
        case ICMP_TIMESTAMP:      return "Timestamp Request";
        case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
        case ICMP_INFO_REQUEST:   return "Information Request";
        case ICMP_INFO_REPLY:     return "Information Reply";
        default:                  return "Unknown";
    }
}

//fonction pour analyser l'en-tête ICMP
int parse_icmp(const u_char *packet, int length, int verbosity, int indent) {
    if(length < 8) {  // En-tête ICMP = 8 octets minimum
        fprintf(stderr, "Erreur: Paquet trop court pour contenir un en-tête ICMP.\n");
        return 0;
    }

    const struct icmphdr *icmp = (const struct icmphdr *)packet;

    // Extraction des champs ICMP
    uint8_t type = icmp->type;
    uint8_t code = icmp->code;
    uint16_t checksum = ntohs(icmp->checksum);
    const char *type_name = get_icmp_type_name(type);

    // Verbosité 2 (synthétique, une ligne)
    if (verbosity == 2) {
        printf("ICMP: type=%u (%s), code=%u\n", type, type_name, code);
    }
    // Verbosité 3 (détaillée)
    else if (verbosity == 3) {
        // Afficher "ICMP Header:" avec indentation
        for(int i = 0; i < indent; i++) printf(" ");
        printf("ICMP Header:\n");
        
        // Afficher Type
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Type:     %u (%s)\n", type, type_name);
        
        // Afficher Code
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Code:     %u\n", code);
        
        // Afficher Checksum
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Checksum: 0x%04x\n", checksum);

        //Parser spécifique pour Echo Request/Reply (ping)
        switch(type) {
            case ICMP_ECHO:
            case ICMP_ECHOREPLY: {
                uint16_t id = ntohs(icmp->un.echo.id);
                uint16_t seq = ntohs(icmp->un.echo.sequence);
                
                for(int i = 0; i < indent+2; i++) printf(" ");
                printf("Identifier: %u, Sequence: %u\n", id, seq);
                break;
            }
            default:
                break;
        }
    }

    return 8;  // En-tête ICMP de base = 8 octets
}

int icmp_v1_summary(const u_char *packet, int caplen, int offset_ip_start, char *resume){
    if(caplen < offset_ip_start + 8) return 0;
    const struct icmphdr *icmp = (const struct icmphdr *)(packet + offset_ip_start);
    switch(icmp->type){
        case ICMP_ECHO: if(strlen(resume)<240) strcat(resume, " EchoReq"); break;
        case ICMP_ECHOREPLY: if(strlen(resume)<240) strcat(resume, " EchoRep"); break;
        case ICMP_DEST_UNREACH: if(strlen(resume)<240) strcat(resume, " Unreach"); break;
        case ICMP_TIME_EXCEEDED: if(strlen(resume)<240) strcat(resume, " TimeEx"); break;
        case ICMP_REDIRECT: if(strlen(resume)<240) strcat(resume, " Redirect"); break;
        default: {
            char tmp[16]; snprintf(tmp,sizeof(tmp)," T%u",icmp->type);
            if(strlen(resume)+strlen(tmp) < 255) strcat(resume,tmp);
        }
    }
    return 1;
}