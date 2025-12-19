/**
 * Analyseur de segments TCP 
 * 
 * Ce module implémente le parsing des segments TCP conformément à la RFC 793.
 * 
 */

#include "tcp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "../util/safe_string.h"
#include "../util/textutils.h"
#include "../include/detection.h"

/* Définitions des flags TCP si non disponibles */
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x80
#endif

/* Table des flags TCP pour affichage */
static const struct { uint8_t mask; const char *name; } tcp_flags[] = {
    {TH_SYN, "SYN"}, {TH_ACK, "ACK"}, {TH_FIN, "FIN"}, {TH_RST, "RST"},
    {TH_PUSH, "PSH"}, {TH_URG, "URG"}, {TH_ECE, "ECE"}, {TH_CWR, "CWR"}
};
#define TCP_FLAGS_COUNT (sizeof(tcp_flags) / sizeof(tcp_flags[0]))

/* Table des services TCP connus */
static const struct { uint16_t port; const char *name; } tcp_services[] = {
    {22, "SSH"}, {3306, "MySQL"}, {5432, "PostgreSQL"}, {6379, "Redis"},
    {27017, "MongoDB"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"},
    {3389, "RDP"}, {5900, "VNC"}, {1433, "MSSQL"}, {389, "LDAP"}, {636, "LDAPS"}
};
#define TCP_SERVICES_COUNT (sizeof(tcp_services) / sizeof(tcp_services[0]))

/* Recherche un service TCP par port */
static const char *lookup_tcp_service(uint16_t sp, uint16_t dp) {
    for(size_t i = 0; i < TCP_SERVICES_COUNT; i++) {
        if(sp == tcp_services[i].port || dp == tcp_services[i].port)
            return tcp_services[i].name;
    }
    return NULL;
}

/* Construit la chaîne des flags TCP */
static void build_flags_str(uint8_t flags, char *buf, size_t bufsize) {
    buf[0] = '\0';
    for(size_t i = 0; i < TCP_FLAGS_COUNT; i++) {
        if(flags & tcp_flags[i].mask) {
            if(buf[0]) safe_strcat(buf, " ", bufsize);
            safe_strcat(buf, tcp_flags[i].name, bufsize);
        }
    }
}

// Verbosité 2-3 : parse et affiche l'en-tête TCP

int parse_tcp(const u_char *packet, int length, int verbosity, int indent, uint16_t *src_port, uint16_t *dst_port, uint8_t *flags) {
    if (length < (int)sizeof(struct tcphdr)) {
        fprintf(stderr, "TCP: Packet too short (need %zu, got %d)\n",
                sizeof(struct tcphdr), length);
        return 0;
    }

    const struct tcphdr *tcp = (const struct tcphdr *)packet;
    
    /* Extraction des champs de l'en-tête */
    *src_port = ntohs(tcp->source);
    *dst_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack_seq);
    int header_len = tcp->doff * 4;
    uint16_t window = ntohs(tcp->window);
    uint16_t checksum = ntohs(tcp->check);
    uint16_t urgent = ntohs(tcp->urg_ptr);
    
    /* Extraction des flags depuis l'octet 13 */
    const uint8_t *tcp_bytes = (const uint8_t *)tcp;
    *flags = tcp_bytes[13];
    
    /* Vérification de la taille de l'en-tête */
    if (header_len < 20 || header_len > 60) {
        fprintf(stderr, "TCP: Invalid header size (%d)\n", header_len);
        return 0;
    }
    
    if (length < header_len) {
        fprintf(stderr, "TCP: Packet too short for complete header\n");
        return 0;
    }

    /* Construction de la chaîne de flags */
    char flags_str[64];
    build_flags_str(*flags, flags_str, sizeof(flags_str));

    /* Verbosité 2 : affichage synthétique */
    if (verbosity == 2) {
        print_indent(indent);
        printf("TCP: %u -> %u [%s] Seq=%u Ack=%u Win=%u\n",
               *src_port, *dst_port, flags_str, seq, ack, window);
    }
    /* Verbosité 3 : affichage détaillé */
    else if (verbosity == 3) {
        print_indent(indent);
        printf("[L4] TCP Header:\n");
        
        print_indent(indent);
        printf("      Source Port:      %u\n", *src_port);
        
        print_indent(indent);
        printf("      Dest Port:        %u\n", *dst_port);
        
        print_indent(indent);
        printf("      Sequence Number:  %u\n", seq);
        
        print_indent(indent);
        printf("      Ack Number:       %u\n", ack);
        
        print_indent(indent);
        printf("      Data Offset:      %d bytes\n", header_len);
        
        print_indent(indent);
        printf("      Flags:            [%s] (0x%02x)\n", flags_str, *flags);
        
        print_indent(indent);
        printf("      Window:           %u\n", window);
        
        print_indent(indent);
        printf("      Checksum:         0x%04x\n", checksum);
        
        if (*flags & TH_URG) {
            print_indent(indent);
            printf("      Urgent Pointer:   %u\n", urgent);
        }
        
        /* Parsing des options TCP si présentes */
        if (header_len > 20) {
            print_indent(indent);
            printf("      TCP Options:      %d bytes\n", header_len - 20);
            
            /* Parser les options principales */
            int opt_offset = 20;
            while (opt_offset < header_len) {
                uint8_t opt_kind = tcp_bytes[opt_offset];
                
                if (opt_kind == 0) break;  /* End of Options */
                if (opt_kind == 1) {       /* NOP */
                    opt_offset++;
                    continue;
                }
                
                if (opt_offset + 1 >= header_len) break;
                uint8_t opt_len = tcp_bytes[opt_offset + 1];
                
                if (opt_len < 2 || opt_offset + opt_len > header_len) break;
                
                print_indent(indent);
                switch (opt_kind) {
                    case 2:  /* MSS */
                        if (opt_len == 4) {
                            uint16_t mss = (uint16_t)((tcp_bytes[opt_offset+2] << 8) | 
                                                       tcp_bytes[opt_offset+3]);
                            printf("        - MSS: %u\n", mss);
                        }
                        break;
                    case 3:  /* Window Scale */
                        if (opt_len == 3) {
                            printf("        - Window Scale: %u\n", tcp_bytes[opt_offset+2]);
                        }
                        break;
                    case 4:  /* SACK Permitted */
                        printf("        - SACK Permitted\n");
                        break;
                    case 8:  /* Timestamps */
                        if (opt_len == 10) {
                            uint32_t ts_val = (uint32_t)((tcp_bytes[opt_offset+2] << 24) |
                                                          (tcp_bytes[opt_offset+3] << 16) |
                                                          (tcp_bytes[opt_offset+4] << 8) |
                                                           tcp_bytes[opt_offset+5]);
                            uint32_t ts_ecr = (uint32_t)((tcp_bytes[opt_offset+6] << 24) |
                                                          (tcp_bytes[opt_offset+7] << 16) |
                                                          (tcp_bytes[opt_offset+8] << 8) |
                                                           tcp_bytes[opt_offset+9]);
                            printf("        - Timestamps: TSval=%u, TSecr=%u\n", ts_val, ts_ecr);
                        }
                        break;
                    default:
                        printf("        - Option %u (%u bytes)\n", opt_kind, opt_len);
                        break;
                }
                
                opt_offset += opt_len;
            }
        }
    }

    return header_len;
}

/**
 * @brief Génère un résumé des flags TCP pour la verbosité 1
 * @param packet Paquet complet
 * @param caplen Longueur capturée
 * @param offset_transport Offset vers l'en-tête TCP
 * @param payload_len Longueur de la charge utile TCP
 * @param resume Buffer de sortie pour le résumé
 * @param src_ip Adresse IP source (chaîne de caractères)
 * @param dst_ip Adresse IP destination (chaîne de caractères)
 * @return 1 si succès, 0 si erreur
 */
int tcp_v1_flags_summary(const u_char *packet, int caplen, int offset_transport, 
                         int payload_len, char *resume, const char *src_ip, const char *dst_ip) {
    if(caplen < offset_transport + (int)sizeof(struct tcphdr)) return 0;
    
    /* Ajouter le préfixe TCP */
    safe_strcat(resume, " | TCP", RESUME_BUFFER_SIZE);
    
    /* Utiliser l'octet des flags directement */
    const uint8_t *tcp_bytes = packet + offset_transport;
    uint8_t fl = tcp_bytes[13];
    
    /* Déterminer le flag à afficher selon la priorité */
    const char *flag_str = NULL;
    if(fl & TH_SYN) {
        flag_str = (fl & TH_ACK) ? " SYN-ACK" : " SYN";
    } else if(fl & TH_RST) {
        flag_str = " RST";
    } else if(fl & TH_FIN) {
        flag_str = " FIN";
    } else if((fl & TH_PUSH) && (fl & TH_ACK)) {
        flag_str = " PSH-ACK";
    } else if(fl & TH_ACK) {
        flag_str = " ACK";
    }
    
    if(flag_str) {
        safe_strcat(resume, flag_str, RESUME_BUFFER_SIZE);
    }
    
    /* Indication ECN si présent */
    if(fl & (TH_ECE | TH_CWR)) {
        safe_strcat(resume, " [ECN]", RESUME_BUFFER_SIZE);
    }
    
    /* Extraction des ports pour affichage */
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + offset_transport);
    uint16_t sp = ntohs(tcp->source), dp = ntohs(tcp->dest);
    
    /* Indication si paquet sans payload - annoter avec le service si connu */
    if(payload_len <= 0) {
        const char *service = get_tcp_service_name(sp, dp);
        
        if(service) {
            char hint[128];
            snprintf(hint, sizeof(hint), " (->%s, no payload) %s[%u] -> %s[%u]", 
                     service, src_ip, sp, dst_ip, dp);
            safe_strcat(resume, hint, RESUME_BUFFER_SIZE);
        } else {
            char hint[96];
            snprintf(hint, sizeof(hint), " (no payload) %s[%u] -> %s[%u]", 
                     src_ip, sp, dst_ip, dp);
            safe_strcat(resume, hint, RESUME_BUFFER_SIZE);
        }
    }
    
    return 1;
}


int tcp_v1_ports_summary(const u_char *packet, int caplen, int offset_transport, 
                         char *resume, const char *src_ip, const char *dst_ip) {
    if(caplen < offset_transport + (int)sizeof(struct tcphdr)) return 0;
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + offset_transport);
    uint16_t sp = ntohs(tcp->source), dp = ntohs(tcp->dest);
    
    /* Identifier les services connus non parsés par défaut */
    const char *service = lookup_tcp_service(sp, dp);
    
    char tmp[128];
    if(service) {
        snprintf(tmp, sizeof(tmp), " %s[%u] -> %s[%u] (%s)", src_ip, sp, dst_ip, dp, service);
    } else {
        snprintf(tmp, sizeof(tmp), " %s[%u] -> %s[%u]", src_ip, sp, dst_ip, dp);
    }
    safe_strcat(resume, tmp, RESUME_BUFFER_SIZE);
    return 1;
}
