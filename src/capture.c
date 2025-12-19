/**
 * Ce module implémente la fonction packet_handler() qui est appelée par
 * pcap_loop() pour chaque paquet reçu. Il coordonne l'analyse couche par
 * couche
 */

#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include "capture.h"
#include "hexdump.h"
#include "detection.h"
#include "dispatch.h"
#include "protocoles.h"
#include "util/safe_string.h"
#include "util/display_constants.h"

/* Table des EtherTypes connus non parsés en détail */
static const struct { uint16_t type; const char *name; } known_ethertypes[] = {
    {0x8100, "802.1Q VLAN"},
    {0x88CC, "LLDP"},
    {0x887B, "HomePlug AV"},
    {0x8863, "PPPoE Discovery"},
    {0x8864, "PPPoE Session"},
    {0x88F7, "PTP"}
};
#define KNOWN_ETHERTYPES_COUNT (sizeof(known_ethertypes) / sizeof(known_ethertypes[0]))

/* Recherche un EtherType connu, retourne NULL si non trouvé */
static const char *lookup_ethertype(uint16_t type) {
    for (size_t i = 0; i < KNOWN_ETHERTYPES_COUNT; i++) {
        if (known_ethertypes[i].type == type) return known_ethertypes[i].name;
    }
    return NULL;
}

/* Affiche le hexdump des données restantes (verbosité 3 uniquement) */
static void dump_remaining(const u_char *packet, int caplen, int offset, int indent) {
    int remaining = caplen - offset;
    if (remaining <= 0) return;
    int to_dump = remaining > MAX_HEXDUMP_BYTES ? MAX_HEXDUMP_BYTES : remaining;
    print_indent(indent);
    printf("Remaining data (%d bytes", remaining);
    if (remaining > MAX_HEXDUMP_BYTES) printf(", first %d shown", to_dump);
    printf("):\n");
    print_hexdump(packet + offset, to_dump);
}

/**
 * Traite la couche transport pour le niveau de verbosité 1 (concis)
 * Factorise le traitement de la couche 4 pour les paquets IPv4 et IPv6.
 * 
 * @param packet   Pointeur vers le paquet complet (depuis Ethernet)
 * @param caplen   Longueur totale capturée
 * @param l4_offset Offset du début de la couche 4 dans le paquet
 * @param protocol Numéro de protocole (IPPROTO_TCP, IPPROTO_UDP, etc.)
 * @param resume   Buffer de sortie pour construire le résumé
 * @param src_ip   Adresse IP source (pour affichage TCP/UDP)
 * @param dst_ip   Adresse IP destination (pour ICMP/TCP/UDP)
 */
static void handle_transport_layer_v1(const u_char *packet, int caplen, 
                                       int l4_offset, uint8_t protocol,
                                       char *resume, const char *src_ip, const char *dst_ip) {
    // Traitement ICMP (IPv4 uniquement)
    if(protocol == IPPROTO_ICMP && dst_ip != NULL) { 
        icmp_v1_summary_with_ip(packet, caplen, l4_offset, resume, dst_ip);
    }
    // Traitement ICMPv6 (IPv6 uniquement)
    else if(protocol == IPPROTO_ICMPV6) {
        icmpv6_v1_summary(packet, caplen, l4_offset, resume, dst_ip);
    }
    // Traitement TCP
    else if(protocol == IPPROTO_TCP) { 
        // Calculer la longueur du payload TCP pour la détection applicative
        if(caplen >= l4_offset + (int)sizeof(struct tcphdr)) {
            const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4_offset);
            int tcp_header_len = tcp->doff * 4;  /* doff = nombre de mots de 32 bits */
            int tcp_payload_len = caplen - l4_offset - tcp_header_len;
            tcp_v1_flags_summary(packet, caplen, l4_offset, tcp_payload_len, resume, src_ip, dst_ip);
        } else {
            tcp_v1_flags_summary(packet, caplen, l4_offset, 0, resume, src_ip, dst_ip);
        }
        
        /* Détection et traitement des protocoles applicatifs TCP */
        if(caplen >= l4_offset + (int)sizeof(struct tcphdr)) {
            const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4_offset);
            uint16_t sp = ntohs(tcp->source), dp = ntohs(tcp->dest);
            int tcp_header_len = tcp->doff * 4;
            int tcp_payload_offset = l4_offset + tcp_header_len;
            int tcp_payload_len = caplen - tcp_payload_offset;
            const u_char *tcp_payload_start = packet + tcp_payload_offset;
            
            /* Détection basée sur les ports (check_tls=0 pour détecter HTTPS même sans handshake) */
            app_proto_tcp_t detected = detect_app_tcp(sp, dp, tcp_payload_len, 
                                                       tcp_payload_start, 0);
            if(detected != APP_PROTO_TCP_NONE) {
                process_app_tcp_v1(detected, packet, caplen, tcp_payload_offset, 
                                   resume, sp, dp, src_ip, dst_ip);
            } else if(tcp_payload_len > 0) {
                /* Afficher les ports génériques seulement si payload présent mais non reconnu
                 * Les paquets sans payload ont déjà les ports dans tcp_v1_flags_summary() */
                tcp_v1_ports_summary(packet, caplen, l4_offset, resume, src_ip, dst_ip);
            }
        }
    }
    /* Traitement UDP */
    else if(protocol == IPPROTO_UDP) { 
        /* Détection et traitement des protocoles applicatifs UDP */
        if(caplen >= l4_offset + (int)sizeof(struct udphdr)) {
            const struct udphdr *udp = (const struct udphdr *)(packet + l4_offset);
            uint16_t sp = ntohs(udp->source), dp = ntohs(udp->dest);
            int udp_payload_offset = l4_offset + 8;  /* En-tête UDP = 8 octets fixes */
            
            app_proto_udp_t detected = detect_app_udp(sp, dp);
            if(detected != APP_PROTO_UDP_NONE) {
                process_app_udp_v1(detected, packet, caplen, udp_payload_offset, resume, sp, dp, src_ip, dst_ip);
            } else {
                /* Afficher les ports génériques si pas d'application reconnue */
                udp_v1_ports_summary(packet, caplen, l4_offset, resume, src_ip, dst_ip);
            }
        }
    }
}

/**
 * @brief Traite la couche transport pour les niveaux de verbosité 2 et 3
 * 
 * Cette fonction factorise le traitement de la couche 4 pour les paquets
 * IPv4 et IPv6 en mode détaillé (multi-lignes structurées).
 * 
 * Flux de traitement :
 * 1. Parse du protocole transport (TCP/UDP/ICMP)
 * 2. Mise à jour de l'offset et de l'indentation
 * 3. Détection du protocole applicatif (si TCP/UDP)
 * 4. Dispatch vers le parseur applicatif approprié
 * 
 * @param packet    Pointeur vers le paquet complet (depuis Ethernet)
 * @param caplen    Longueur totale capturée
 * @param offset    Pointeur vers l'offset courant (modifié en sortie)
 * @param indent    Pointeur vers l'indentation courante (modifié en sortie)
 * @param protocol  Numéro de protocole de couche 4 (IPPROTO_TCP, IPPROTO_UDP, etc.)
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param is_ipv6   Indicateur IPv6 (1) ou IPv4 (0) - utilisé pour ICMP vs ICMPv6
 */
static void handle_transport_layer_v2v3(const u_char *packet, int caplen,
                                         int *offset, int *indent,
                                         uint8_t protocol, int verbosity,
                                         int is_ipv6) {
    // Traitement UDP
    if(protocol == IPPROTO_UDP) {
        uint16_t src_port, dst_port;
        int udp_len = parse_udp(packet + *offset, caplen - *offset, verbosity, *indent, &src_port, &dst_port);
        if(udp_len > 0) {
            *offset += udp_len;
            *indent += 2;
            
            // Détection et traitement des protocoles applicatifs UDP
            app_proto_udp_t detected = detect_app_udp(src_port, dst_port);
            if(detected != APP_PROTO_UDP_NONE) {
                int consumed = process_app_udp_v2v3(detected, packet + *offset, caplen - *offset, verbosity, *indent, offset);
                if(consumed > 0) {
                    *indent += 2;
                }
            }
        }
    }
    // Traitement TCP
    else if(protocol == IPPROTO_TCP) {
        uint16_t src_port, dst_port;
        uint8_t flags;
        int tcp_len = parse_tcp(packet + *offset, caplen - *offset, verbosity, *indent, &src_port, &dst_port, &flags);
        if(tcp_len > 0) {
            *offset += tcp_len;
            *indent += 2;
            
            // Détection avec vérification TLS pour différencier HTTPS/SMTPS/etc.
            app_proto_tcp_t detected = detect_app_tcp(src_port, dst_port,
                                                      caplen - *offset,
                                                      packet + *offset, 1);
            if(detected != APP_PROTO_TCP_NONE) {
                int consumed = process_app_tcp_v2v3(detected, packet + *offset, caplen - *offset, verbosity, *indent, offset, src_port, dst_port);
                if(consumed > 0) {
                    *indent += 2;
                }
            }
        }
    }
    // Traitement ICMP (IPv4 uniquement)
    else if(protocol == IPPROTO_ICMP && !is_ipv6) {
        int icmp_len = parse_icmp(packet + *offset, caplen - *offset, verbosity, *indent);
        if(icmp_len > 0) {
            *offset += icmp_len;
            *indent += 2;
        }
    }
    // Traitement ICMPv6 (IPv6 uniquement)
    else if(protocol == IPPROTO_ICMPV6 && is_ipv6) {
        int icmpv6_len = parse_icmpv6(packet + *offset, caplen - *offset, verbosity, *indent);
        if(icmpv6_len > 0) {
            *offset += icmpv6_len;
            *indent += 2;
        }
    }
}

/**
 * Callback de traitement des paquets pour pcap_loop()
 * Cette fonction est appelée automatiquement par libpcap pour chaque paquet
 * capturé. Elle implémente le traitement complet d'une trame Ethernet :

 * @param args   Données utilisateur passées à pcap_loop() (capture_args_t*)
 * @param header Métadonnées du paquet (timestamp, longueurs)
 * @param packet Pointeur vers les données brutes de la trame
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    capture_args_t *capture = (capture_args_t *)args;
    int verbosity = capture->verbosity;
    
    // Compteur statique de paquets pour numérotation (verbosité 2-3)
    static int packet_count = 0;
    packet_count++;
    
    // Cache d'optimisation des timestamps
    // Évite les appels répétés à localtime() pour les paquets dans la même seconde
    static time_t last_sec = 0;
    static struct tm last_tm;
    static char last_timestamp[32];

    // Extraction des longueurs du paquet
    int caplen = (int)header->caplen;   // Octets effectivement capturés
    int wirelen = (int)header->len;      // Taille originale sur le réseau

    // Analyse de l'en-tête Ethernet
    const struct ether_header *eth_header = (const struct ether_header *)packet;
    uint16_t ethertype = ntohs(eth_header->ether_type);
    
    // Buffer pour construire le résumé (verbosité 1 uniquement)
    char resume[RESUME_BUFFER_SIZE] = "";

    // TRAITEMENT VERBOSITÉ 1 (format concis une ligne)
    if (verbosity == 1) {
        // Protocole ARP (Address Resolution Protocol)
        if(ethertype == ETHERTYPE_ARP){
            snprintf(resume, RESUME_BUFFER_SIZE, "ARP");
            arp_v1_summary(packet, caplen, ETHER_HDR_LEN, resume);
        } 
        // Protocole RARP (Reverse ARP)
        else if(ethertype == ETHERTYPE_REVARP){
            snprintf(resume, RESUME_BUFFER_SIZE, "RARP");
            rarp_v1_summary(packet, caplen, ETHER_HDR_LEN, resume);
        } 
        // Protocole IPv4
        else if(ethertype == ETHERTYPE_IP){
            snprintf(resume, RESUME_BUFFER_SIZE, "IPv4");
            if(caplen >= ETHER_HDR_LEN + (int)sizeof(struct iphdr)){
                /* Calcul de l'offset de la couche 4 (transport) */
                const struct iphdr *ip = (const struct iphdr *)(packet + ETHER_HDR_LEN);
                int ihl = ip->ihl * 4;  /* IHL = longueur en-tête en mots de 32 bits */
                if((int)caplen >= ETHER_HDR_LEN + ihl){
                    int l4off = ETHER_HDR_LEN + ihl;
                    
                    /* Extraction des IPs source et destination pour affichage */
                    char src_ip[INET_ADDRSTRLEN];
                    char dst_ip[INET_ADDRSTRLEN];
                    struct in_addr src_addr = { .s_addr = ip->saddr };
                    struct in_addr dst_addr = { .s_addr = ip->daddr };
                    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
                    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));
                    
                    /* Dispatch vers la couche transport (fonction factorisée) */
                    handle_transport_layer_v1(packet, caplen, l4off, ip->protocol, 
                                              resume, src_ip, dst_ip);
                }
            }
        } 
        // Protocole IPv6
        else if(ethertype == ETHERTYPE_IPV6){
            snprintf(resume, RESUME_BUFFER_SIZE, "IPv6");
            if(caplen >= ETHER_HDR_LEN + (int)sizeof(struct ip6_hdr)){
                /* Parser IPv6 pour gérer les en-têtes d'extension (Hop-by-Hop, etc.) */
                uint8_t final_protocol;
                int ip6_len = parse_ipv6(packet + ETHER_HDR_LEN, caplen - ETHER_HDR_LEN, 
                                         0, 0, &final_protocol);  /* verbosity=0 = silencieux */
                if(ip6_len > 0) {
                    int l4off = ETHER_HDR_LEN + ip6_len;
                    
                    /* Extraction des IPs source et destination IPv6 */
                    char src_ip6[INET6_ADDRSTRLEN] = "";
                    char dst_ip6[INET6_ADDRSTRLEN] = "";
                    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + ETHER_HDR_LEN);
                    inet_ntop(AF_INET6, &ip6->ip6_src, src_ip6, sizeof(src_ip6));
                    inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip6, sizeof(dst_ip6));
                    
                    /* Dispatch vers la couche transport avec le protocole final */
                    handle_transport_layer_v1(packet, caplen, l4off, final_protocol, resume, src_ip6, dst_ip6);
                }
            }
        }
        // EtherTypes connus mais non parsés en détail
        else {
            const char *eth_name = lookup_ethertype(ethertype);
            if (eth_name) snprintf(resume, RESUME_BUFFER_SIZE, "%s", eth_name);
        }
        
        /* Fallback pour les EtherTypes inconnus */
        if(strlen(resume) == 0) {
            snprintf(resume, sizeof(resume), "Unknown EtherType 0x%04x", ethertype);
        }
        
        /* Formatage du timestamp avec cache d'optimisation */
        if(header->ts.tv_sec != last_sec) {
            struct tm *tm_info = localtime(&header->ts.tv_sec);
            last_tm = *tm_info;
            last_sec = header->ts.tv_sec;
            strftime(last_timestamp, sizeof(last_timestamp), "%Hh%Mm%Ss", &last_tm);
        }
        
        /* Affichage de la ligne de résumé */
        printf("%s | %s | len: %u%s\n", 
               last_timestamp,
               resume, wirelen, 
               caplen < wirelen ? " (truncated)" : "");
        return;  /* Fin du traitement pour verbosité 1 */
    }

    // TRAITEMENT VERBOSITÉS 2 ET 3 (format détaillé)
    if(verbosity >= 2) {
        /* En-tête de paquet avec numéro et taille */
        printf("\nPacket %d - %u bytes captured%s\n", 
               packet_count, caplen, caplen < wirelen ? " (truncated)" : "");
        
        int indent = 0;  /* Niveau d'indentation pour affichage hiérarchique */
        int offset = 0;  /* Position courante dans le paquet */
        uint16_t ethertype;

        // Analyse de la couche 2 : Ethernet
        offset = parse_ethernet(packet, caplen, verbosity, indent, &ethertype);
        indent += 2;  /* Augmentation de l'indentation pour la couche suivante */

        // Protocole ARP (couche 2, terminal)
        if(ethertype == ETHERTYPE_ARP){
            parse_arp(packet + offset, caplen - offset, verbosity, indent);
        }
        // Protocole RARP (couche 2, terminal)
        else if(ethertype == ETHERTYPE_REVARP){
            parse_rarp(packet + offset, caplen - offset, verbosity, indent);
        }
        // Protocole IPv4 (couche 3)
        else if(ethertype == ETHERTYPE_IP){
            uint8_t proto;
            int ip_hdr_len = parse_ipv4(packet + offset, caplen - offset, verbosity, indent, &proto);
            if(ip_hdr_len == 0) {
                fprintf(stderr, "Error: IPv4 parsing failed, packet skipped\n");
            } else {
                offset += ip_hdr_len;
                indent += 2;
                
                /* Dispatch vers la couche transport (fonction factorisée) */
                handle_transport_layer_v2v3(packet, caplen, &offset, &indent, proto, verbosity, 0);
                
                /* Hexdump des données restantes non parsées (verbosité 3) */
                if(verbosity == 3) dump_remaining(packet, caplen, offset, indent);
            }
        }
        // Protocole IPv6 (couche 3)
        else if (ethertype == ETHERTYPE_IPV6){
            uint8_t next_header;
            int ip6_hdr_len = parse_ipv6(packet + offset, caplen - offset, verbosity, indent, &next_header);
            if(ip6_hdr_len > 0) {
                offset += ip6_hdr_len;
                indent += 2;
                
                /* Dispatch vers la couche transport avec protocole final (après ext. headers) */
                handle_transport_layer_v2v3(packet, caplen, &offset, &indent, next_header, verbosity, 1);
                
                /* Hexdump des données restantes non parsées (verbosité 3) */
                if(verbosity == 3) dump_remaining(packet, caplen, offset, indent);
            }
        }
        // Autres EtherTypes (connus ou non)
        else {
            const char *eth_name = lookup_ethertype(ethertype);
            print_indent(indent);
            if (eth_name) printf("%s (not parsed)\n", eth_name);
            else printf("Unknown EtherType: 0x%04x\n", ethertype);
        }
    }
}
