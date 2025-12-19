/**
 * @file tcp.c
 * @brief Analyseur de segments TCP (couche 4 - Transport)
 * 
 * Ce module implémente le parsing des segments TCP conformément à la RFC 793.
 * TCP (Transmission Control Protocol) assure une transmission fiable,
 * ordonnée et avec contrôle de flux des données.
 * 
 * Protocole IP : 6
 * 
 * Structure de l'en-tête TCP (20-60 octets) :
 * - Port source (16 bits)
 * - Port destination (16 bits)
 * - Numéro de séquence (32 bits)
 * - Numéro d'acquittement (32 bits)
 * - Data Offset (4 bits) : taille de l'en-tête en mots de 32 bits
 * - Flags (9 bits) : NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
 * - Fenêtre (16 bits) : taille de la fenêtre de réception
 * - Checksum (16 bits)
 * - Pointeur urgent (16 bits)
 * - Options (0-40 octets) : MSS, Window Scale, SACK, Timestamps
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "tcp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "../util/safe_string.h"
#include "../util/textutils.h"

/* Définitions des flags TCP si non disponibles */
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x80
#endif

/* ============================================================================
 * FONCTION DE PARSING PRINCIPALE (VERBOSITÉ 2-3)
 * ============================================================================ */

/**
 * @brief Parse et affiche un en-tête TCP
 * @param packet Pointeur vers le début de l'en-tête TCP
 * @param length Longueur restante du paquet
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent Indentation pour l'affichage
 * @param src_port Pointeur de sortie pour le port source
 * @param dst_port Pointeur de sortie pour le port destination
 * @param flags Pointeur de sortie pour les flags TCP
 * @return Taille de l'en-tête TCP ou 0 si erreur
 */
int parse_tcp(const u_char *packet, int length, int verbosity, int indent,
              uint16_t *src_port, uint16_t *dst_port, uint8_t *flags) {
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

    /* Construction de la chaîne de flags avec safe_strcat pour cohérence */
    char flags_str[64] = "";
    if (*flags & TH_SYN) safe_strcat(flags_str, "SYN ", sizeof(flags_str));
    if (*flags & TH_ACK) safe_strcat(flags_str, "ACK ", sizeof(flags_str));
    if (*flags & TH_FIN) safe_strcat(flags_str, "FIN ", sizeof(flags_str));
    if (*flags & TH_RST) safe_strcat(flags_str, "RST ", sizeof(flags_str));
    if (*flags & TH_PUSH) safe_strcat(flags_str, "PSH ", sizeof(flags_str));
    if (*flags & TH_URG) safe_strcat(flags_str, "URG ", sizeof(flags_str));
    if (*flags & TH_ECE) safe_strcat(flags_str, "ECE ", sizeof(flags_str));
    if (*flags & TH_CWR) safe_strcat(flags_str, "CWR ", sizeof(flags_str));
    
    /* Supprimer l'espace final si présent */
    size_t len = strlen(flags_str);
    if (len > 0 && flags_str[len-1] == ' ') {
        flags_str[len-1] = '\0';
    }

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

/* ============================================================================
 * FONCTIONS DE RÉSUMÉ (VERBOSITÉ 1)
 * ============================================================================ */

/**
 * @brief Génère un résumé des flags TCP pour la verbosité 1
 * @param packet Paquet complet
 * @param caplen Longueur capturée
 * @param offset_transport Offset vers l'en-tête TCP
 * @param payload_len Longueur de la charge utile TCP
 * @param resume Buffer de sortie pour le résumé
 * @return 1 si succès, 0 si erreur
 */
int tcp_v1_flags_summary(const u_char *packet, int caplen, int offset_transport, 
                         int payload_len, char *resume) {
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
    
    /* Indication si ACK pur sans payload */
    if((fl & TH_ACK) && payload_len <= 0) {
        safe_strcat(resume, " (no payload)", RESUME_BUFFER_SIZE);
    }
    
    return 1;
}

/**
 * @brief Génère un résumé des ports TCP pour la verbosité 1
 * @param packet Paquet complet
 * @param caplen Longueur capturée
 * @param offset_transport Offset vers l'en-tête TCP
 * @param resume Buffer de sortie pour le résumé
 * @return 1 si succès, 0 si erreur
 */
int tcp_v1_ports_summary(const u_char *packet, int caplen, int offset_transport, char *resume) {
    if(caplen < offset_transport + (int)sizeof(struct tcphdr)) return 0;
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + offset_transport);
    uint16_t sp = ntohs(tcp->source), dp = ntohs(tcp->dest);
    
    /* Identifier les services connus non parsés par défaut */
    const char *service = NULL;
    if(sp == 22 || dp == 22) service = "SSH";
    else if(sp == 3306 || dp == 3306) service = "MySQL";
    else if(sp == 5432 || dp == 5432) service = "PostgreSQL";
    else if(sp == 6379 || dp == 6379) service = "Redis";
    else if(sp == 27017 || dp == 27017) service = "MongoDB";
    else if(sp == 8080 || dp == 8080) service = "HTTP-Alt";
    else if(sp == 8443 || dp == 8443) service = "HTTPS-Alt";
    else if(sp == 3389 || dp == 3389) service = "RDP";
    else if(sp == 5900 || dp == 5900) service = "VNC";
    else if(sp == 1433 || dp == 1433) service = "MSSQL";
    else if(sp == 389 || dp == 389) service = "LDAP";
    else if(sp == 636 || dp == 636) service = "LDAPS";
    
    char tmp[64];
    if(service) {
        snprintf(tmp, sizeof(tmp), " %u>%u (%s)", sp, dp, service);
    } else {
        snprintf(tmp, sizeof(tmp), " %u>%u", sp, dp);
    }
    safe_strcat(resume, tmp, RESUME_BUFFER_SIZE);
    return 1;
}
