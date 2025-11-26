#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "capture.h"
#include "hexdump.h"
#include "protocoles/protocoles.h"

/* Types pour la détection de protocoles */
typedef enum {
    APP_PROTO_TCP_NONE = 0,
    APP_PROTO_TCP_DNS,
    APP_PROTO_TCP_HTTP,
    APP_PROTO_TCP_SMTP,
    APP_PROTO_TCP_IMAP,
    APP_PROTO_TCP_IMAPS,
    APP_PROTO_TCP_POP3,
    APP_PROTO_TCP_POP3S
} app_proto_tcp_t;

typedef enum {
    APP_PROTO_UDP_NONE = 0,
    APP_PROTO_UDP_DNS,
    APP_PROTO_UDP_DHCP
} app_proto_udp_t;

/**
 * Détecte le protocole applicatif TCP basé sur les ports source/destination.
 * Version pour niveau 1 (vérifie payload_len et TLS).
 * @param src_port Port source
 * @param dst_port Port destination
 * @param tcp_payload_len Longueur du payload TCP (pour vérifications spéciales)
 * @param tcp_payload_start Pointeur vers le début du payload TCP (pour détection TLS)
 * @param caplen Longueur capturée totale
 * @param tcp_payload_offset Offset du payload TCP dans le paquet
 * @return Type de protocole détecté
 */
static app_proto_tcp_t detect_app_tcp_v1(uint16_t src_port, uint16_t dst_port,
                                          int tcp_payload_len,
                                          const u_char *tcp_payload_start,
                                          int caplen, int tcp_payload_offset) {
    // DNS (priorité 1) - nécessite payload (pas de DNS dans handshake TCP)
    if(src_port == DNS_PORT || dst_port == DNS_PORT) {
        if(tcp_payload_len > 0) {
            return APP_PROTO_TCP_DNS;
        }
    }
    
    // HTTP (priorité 2) - nécessite payload
    if(src_port == HTTP_PORT_PLAIN || dst_port == HTTP_PORT_PLAIN) {
        if(tcp_payload_len > 0) {
            return APP_PROTO_TCP_HTTP;
        }
    }
    
    // SMTP (priorité 3) - 2 ports possibles, nécessite payload
    if((src_port == SMTP_PORT_PLAIN || dst_port == SMTP_PORT_PLAIN) ||
       (src_port == SMTP_PORT_SUBMISSION || dst_port == SMTP_PORT_SUBMISSION)) {
        if(tcp_payload_len > 0) {
            return APP_PROTO_TCP_SMTP;
        }
    }
    
    // IMAP (priorité 4) - nécessite payload
    if(src_port == IMAP_PORT_PLAIN || dst_port == IMAP_PORT_PLAIN) {
        if(tcp_payload_len > 0) {
            return APP_PROTO_TCP_IMAP;
        }
    }
    
    // IMAPS (priorité 5) - nécessite payload
    if(src_port == IMAP_PORT_SSL || dst_port == IMAP_PORT_SSL) {
        if(tcp_payload_len > 0) {
            return APP_PROTO_TCP_IMAPS;
        }
    }
    
    // POP3 (priorité 6) - nécessite payload
    if(src_port == POP3_PORT_PLAIN || dst_port == POP3_PORT_PLAIN) {
        if(tcp_payload_len > 0) {
            return APP_PROTO_TCP_POP3;
        }
    }
    
    // POP3S (priorité 7) - vérification TLS spéciale
    if(src_port == POP3_PORT_SSL || dst_port == POP3_PORT_SSL) {
        if(tcp_payload_len > 0) {
            // Vérifier si c'est un handshake TLS
            if((unsigned int)caplen > (unsigned int)(tcp_payload_offset + 5)) {
                if(tcp_payload_start[0] == 0x16 && tcp_payload_start[1] == 0x03) {
                    return APP_PROTO_TCP_POP3S; // TLS détecté
                }
            }
            // Sinon, tenter POP3 en clair
            return APP_PROTO_TCP_POP3;
        }
    }
    
    return APP_PROTO_TCP_NONE;
}

/**
 * Détecte le protocole applicatif TCP basé sur les ports source/destination.
 * Version simplifiée pour niveaux 2-3 (pas de vérification payload_len).
 * @param src_port Port source
 * @param dst_port Port destination
 * @param tcp_payload_start Pointeur vers le début du payload TCP (pour détection TLS)
 * @param length Longueur disponible
 * @return Type de protocole détecté
 */
static app_proto_tcp_t detect_app_tcp_v2v3(uint16_t src_port, uint16_t dst_port,
                                            const u_char *tcp_payload_start,
                                            int length) {
    // DNS (priorité 1) - nécessite payload
    if(src_port == DNS_PORT || dst_port == DNS_PORT) {
        if(length > 0) {
            return APP_PROTO_TCP_DNS;
        }
    }
    
    // HTTP (priorité 2) - nécessite payload
    if(src_port == HTTP_PORT_PLAIN || dst_port == HTTP_PORT_PLAIN) {
        if(length > 0) {
            return APP_PROTO_TCP_HTTP;
        }
    }
    
    // SMTP (priorité 3) - 2 ports possibles, nécessite payload
    if((src_port == SMTP_PORT_PLAIN || dst_port == SMTP_PORT_PLAIN) ||
       (src_port == SMTP_PORT_SUBMISSION || dst_port == SMTP_PORT_SUBMISSION)) {
        if(length > 0) {
            return APP_PROTO_TCP_SMTP;
        }
    }
    
    // IMAP (priorité 4) - nécessite payload
    if(src_port == IMAP_PORT_PLAIN || dst_port == IMAP_PORT_PLAIN) {
        if(length > 0) {
            return APP_PROTO_TCP_IMAP;
        }
    }
    
    // IMAPS (priorité 5) - nécessite payload
    if(src_port == IMAP_PORT_SSL || dst_port == IMAP_PORT_SSL) {
        if(length > 0) {
            return APP_PROTO_TCP_IMAPS;
        }
    }
    
    // POP3 (priorité 6) - nécessite payload
    if(src_port == POP3_PORT_PLAIN || dst_port == POP3_PORT_PLAIN) {
        if(length > 0) {
            return APP_PROTO_TCP_POP3;
        }
    }
    
    // POP3S (priorité 7) - vérification TLS spéciale
    if(src_port == POP3_PORT_SSL || dst_port == POP3_PORT_SSL) {
        if(length > 5) {
            if(tcp_payload_start[0] == 0x16 && tcp_payload_start[1] == 0x03) {
                return APP_PROTO_TCP_POP3S; // TLS détecté
            }
        }
        // Sinon, tenter POP3 en clair
        return APP_PROTO_TCP_POP3;
    }
    
    return APP_PROTO_TCP_NONE;
}

/**
 * Détecte le protocole applicatif UDP basé sur les ports source/destination.
 * @param src_port Port source
 * @param dst_port Port destination
 * @return Type de protocole détecté
 */
static app_proto_udp_t detect_app_udp_v1(uint16_t src_port, uint16_t dst_port) {
    // DNS (priorité 1)
    if(src_port == DNS_PORT || dst_port == DNS_PORT) {
        return APP_PROTO_UDP_DNS;
    }
    
    // DHCP (priorité 2)
    if(src_port == DHCP_SERVER_PORT || src_port == DHCP_CLIENT_PORT ||
       dst_port == DHCP_SERVER_PORT || dst_port == DHCP_CLIENT_PORT) {
        return APP_PROTO_UDP_DHCP;
    }
    
    return APP_PROTO_UDP_NONE;
}

/**
 * Traite un protocole TCP détecté pour le niveau 1 (verbosité 1).
 * @param proto Type de protocole détecté
 * @param packet Pointeur vers le paquet complet
 * @param caplen Longueur capturée
 * @param tcp_payload_offset Offset du payload TCP
 * @param resume Buffer de sortie pour le résumé
 * @return 1 si traitement réussi, 0 sinon
 */
static int process_app_tcp_v1(app_proto_tcp_t proto,
                               const u_char *packet, int caplen,
                               int tcp_payload_offset, char *resume) {
    switch(proto) {
        case APP_PROTO_TCP_DNS:
            strcat(resume, " | DNS");
            return dns_v1_summary(packet, caplen, tcp_payload_offset, resume, 1);
            
        case APP_PROTO_TCP_HTTP:
            return http_v1_summary(packet, caplen, tcp_payload_offset, resume);
            
        case APP_PROTO_TCP_SMTP:
            return smtp_v1_summary(packet, caplen, tcp_payload_offset, resume);
            
        case APP_PROTO_TCP_IMAP:
            return imap_v1_summary(packet, caplen, tcp_payload_offset, resume);
            
        case APP_PROTO_TCP_IMAPS:
            return imap_v1_summary(packet, caplen, tcp_payload_offset, resume);
            
        case APP_PROTO_TCP_POP3:
            return pop3_v1_summary(packet, caplen, tcp_payload_offset, resume);
            
        case APP_PROTO_TCP_POP3S:
            strcat(resume, " | POP3S (TLS)");
            return 1;
            
        default:
            return 0;
    }
}

/**
 * Traite un protocole UDP détecté pour le niveau 1 (verbosité 1).
 * @param proto Type de protocole détecté
 * @param packet Pointeur vers le paquet complet
 * @param caplen Longueur capturée
 * @param udp_payload_offset Offset du payload UDP
 * @param resume Buffer de sortie pour le résumé
 * @return 1 si traitement réussi, 0 sinon
 */
static int process_app_udp_v1(app_proto_udp_t proto,
                               const u_char *packet, int caplen,
                               int udp_payload_offset, char *resume) {
    switch(proto) {
        case APP_PROTO_UDP_DNS:
            strcat(resume, " | DNS");
            return dns_v1_summary(packet, caplen, udp_payload_offset, resume, 0);
            
        case APP_PROTO_UDP_DHCP:
            strcat(resume, " | DHCP");
            return dhcp_v1_summary(packet, caplen, udp_payload_offset, resume);
            
        default:
            return 0;
    }
}

/**
 * Traite un protocole TCP détecté pour les niveaux 2-3.
 * @param proto Type de protocole détecté
 * @param packet Pointeur vers le payload TCP
 * @param length Longueur disponible
 * @param verbosity Niveau de verbosité
 * @param indent Indentation
 * @param offset Pointeur vers l'offset (mis à jour)
 * @return Nombre d'octets consommés
 */
static int process_app_tcp_v2v3(app_proto_tcp_t proto,
                                 const u_char *packet, int length,
                                 int verbosity, int indent,
                                 int *offset) {
    int consumed = 0;
    
    switch(proto) {
        case APP_PROTO_TCP_DNS: {
            int is_resp;
            char qname[DNS_MAX_NAME_LEN];
            consumed = parse_dns(packet, length, verbosity, indent, 1, &is_resp, qname, sizeof(qname));
            break;
        }
        
        case APP_PROTO_TCP_HTTP:
            consumed = parse_http(packet, length, verbosity, indent);
            break;
            
        case APP_PROTO_TCP_SMTP:
            consumed = parse_smtp(packet, length, verbosity, indent);
            break;
            
        case APP_PROTO_TCP_IMAP:
            consumed = parse_imap(packet, length, verbosity, indent);
            break;
            
        case APP_PROTO_TCP_IMAPS:
            // Détection TLS pour IMAPS
            if(length > 5) {
                if(packet[0] == 0x16 && packet[1] == 0x03) {
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("IMAPS (TLS Handshake) – content not parsed\n");
                    consumed = 0; // Pas de parsing TLS
                } else {
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("IMAPS (Encrypted or Non-handshake segment)\n");
                    consumed = 0;
                }
            }
            break;
            
        case APP_PROTO_TCP_POP3:
            consumed = parse_pop3(packet, length, verbosity, indent);
            break;
            
        case APP_PROTO_TCP_POP3S:
            // Détection TLS pour POP3S
            if(length > 5) {
                if(packet[0] == 0x16 && packet[1] == 0x03) {
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("POP3S (TLS Handshake) – content not parsed\n");
                    consumed = 0;
                } else {
                    // Tenter POP3 en clair avant TLS
                    consumed = parse_pop3(packet, length, verbosity, indent);
                    if(consumed == 0) {
                        for(int i = 0; i < indent; i++) printf(" ");
                        printf("POP3S (Encrypted or Non-handshake segment)\n");
                    }
                }
            }
            break;
            
        default:
            consumed = 0;
            break;
    }
    
    if(consumed > 0 && offset != NULL) {
        *offset += consumed;
    }
    
    return consumed;
}

/**
 * Traite un protocole UDP détecté pour les niveaux 2-3.
 * @param proto Type de protocole détecté
 * @param packet Pointeur vers le payload UDP
 * @param length Longueur disponible
 * @param verbosity Niveau de verbosité
 * @param indent Indentation
 * @param offset Pointeur vers l'offset (mis à jour)
 * @return Nombre d'octets consommés
 */
static int process_app_udp_v2v3(app_proto_udp_t proto,
                                 const u_char *packet, int length,
                                 int verbosity, int indent,
                                 int *offset) {
    int consumed = 0;
    
    switch(proto) {
        case APP_PROTO_UDP_DNS: {
            int is_resp;
            char qname[DNS_MAX_NAME_LEN];
            consumed = parse_dns(packet, length, verbosity, indent, 0, &is_resp, qname, sizeof(qname));
            break;
        }
        
        case APP_PROTO_UDP_DHCP:
            parse_dhcp(packet, length, verbosity, indent);
            consumed = length;
            break;
            
        default:
            consumed = 0;
            break;
    }
    
    if(consumed > 0 && offset != NULL) {
        *offset += consumed;
    }
    
    return consumed;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    capture_args_t *capture = (capture_args_t *)args;
    int verbosity = capture->verbosity;
    static int packet_count = 0;
    packet_count++;

    //Déterminer le type de paquet pour affichage niveau 1
    const struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ethertype = ntohs(eth_header->ether_type);
    char resume[256] = "";

    //Niveau 1: affichage très concis
    if (verbosity == 1) {
        if(ethertype == ETHERTYPE_ARP){ //ARP
            strcat(resume, "ARP");
            arp_v1_summary(packet, header->caplen, 14, resume); //ajout who-has / is-at 
        } 
        else if(ethertype == ETHERTYPE_REVARP){ //RARP
            strcat(resume, "RARP");
            rarp_v1_summary(packet, header->caplen, 14, resume); //ajout who-is / is-at 
        }
        else if(ethertype == ETHERTYPE_IP){ //IPv4
            strcat(resume, "IPv4");
            if(header->caplen >= 14 + (int)sizeof(struct iphdr)){
                //calcul de l'offset de la couche 4
                const struct iphdr *ip = (const struct iphdr *)(packet + 14);
                int ihl = ip->ihl * 4;
                if((int)header->caplen >= 14 + ihl){
                    int l4off = 14 + ihl;
                    if(ip->protocol == IPPROTO_ICMP){ //ICMP
                        strcat(resume, " | ICMP");
                        // Extraire l'adresse IP de destination
                        char dst_ip[INET_ADDRSTRLEN];
                        struct in_addr dst_addr = { .s_addr = ip->daddr };
                        inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));
                        icmp_v1_summary_with_ip(packet, header->caplen, l4off, resume, dst_ip);
                    } 
                    else if(ip->protocol == IPPROTO_TCP){ //TCP
                        strcat(resume, " | TCP");
                        tcp_v1_flags_summary(packet, header->caplen, l4off, resume);
                        // Applications courantes
                        if((int)header->caplen >= l4off + (int)sizeof(struct tcphdr)){
                            const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4off);
                            uint16_t sp = ntohs(tcp->source), dp = ntohs(tcp->dest);
                            int tcp_header_len = tcp->doff * 4;
                            int tcp_payload_offset = l4off + tcp_header_len;
                            int tcp_payload_len = header->caplen - tcp_payload_offset;
                            const u_char *tcp_payload_start = packet + tcp_payload_offset;
                            
                            app_proto_tcp_t detected = detect_app_tcp_v1(sp, dp, tcp_payload_len,
                                                                        tcp_payload_start,
                                                                        header->caplen, tcp_payload_offset);
                            if(detected != APP_PROTO_TCP_NONE) {
                                process_app_tcp_v1(detected, packet, header->caplen,
                                                   tcp_payload_offset, resume);
                            }
                        }
                    } 
                    else if(ip->protocol == IPPROTO_UDP){ //UDP
                        strcat(resume, " | UDP");
                        // Applications courantes
                        if((int)header->caplen >= l4off + (int)sizeof(struct udphdr)){
                            const struct udphdr *udp = (const struct udphdr *)(packet + l4off);
                            uint16_t sp = ntohs(udp->source), dp = ntohs(udp->dest);
                            int udp_payload_off = l4off + 8;
                            
                            app_proto_udp_t detected = detect_app_udp_v1(sp, dp);
                            if(detected != APP_PROTO_UDP_NONE) {
                                process_app_udp_v1(detected, packet, header->caplen,
                                                  udp_payload_off, resume);
                            } else {
                                // ports génériques si pas d'application reconnue
                                udp_v1_ports_summary(packet, header->caplen, l4off, resume);
                            }
                        }
                    }
                }
            }
        } 
        else if(ethertype == ETHERTYPE_IPV6){ //IPv6
            strcat(resume, "IPv6");
            if(header->caplen >= 14 + (int)sizeof(struct ip6_hdr)){
                //calcul de l'offset de la couche 4
                const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + 14);
                int l4off = 14 + sizeof(struct ip6_hdr);
                uint8_t nxt = ip6->ip6_nxt;
                if(nxt == IPPROTO_ICMPV6){  //ICMPv6
                    strcat(resume, " | ICMPv6");
                    icmpv6_v1_summary(packet, header->caplen, l4off, resume);
                } 
                else if(nxt == IPPROTO_TCP){ //TCP
                    strcat(resume, " | TCP");
                    tcp_v1_flags_summary(packet, header->caplen, l4off, resume);
                    // Applications courantes
                    if((int)header->caplen >= l4off + (int)sizeof(struct tcphdr)){
                        const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4off);
                        uint16_t sp = ntohs(tcp->source), dp = ntohs(tcp->dest);
                        int tcp_header_len = tcp->doff * 4;
                        int tcp_payload_offset = l4off + tcp_header_len;
                        int tcp_payload_len = header->caplen - tcp_payload_offset;
                        const u_char *tcp_payload_start = packet + tcp_payload_offset;
                        
                        app_proto_tcp_t detected = detect_app_tcp_v1(sp, dp, tcp_payload_len,
                                                                    tcp_payload_start,
                                                                    header->caplen, tcp_payload_offset);
                        if(detected != APP_PROTO_TCP_NONE) {
                            process_app_tcp_v1(detected, packet, header->caplen,
                                               tcp_payload_offset, resume);
                        }
                    }
                } 
                else if(nxt == IPPROTO_UDP){ //UDP
                    strcat(resume, " | UDP");
                    // Applications courantes
                    if((int)header->caplen >= l4off + (int)sizeof(struct udphdr)){
                        const struct udphdr *udp = (const struct udphdr *)(packet + l4off);
                        uint16_t sp = ntohs(udp->source), dp = ntohs(udp->dest);
                        int udp_payload_off = l4off + 8; // taille en-tête UDP = 8 octets
                        
                        app_proto_udp_t detected = detect_app_udp_v1(sp, dp);
                        if(detected != APP_PROTO_UDP_NONE) {
                            process_app_udp_v1(detected, packet, header->caplen,
                                              udp_payload_off, resume);
                        } else {
                            // ports génériques si pas d'application reconnue
                            udp_v1_ports_summary(packet, header->caplen, l4off, resume);
                        }
                    }
                }
            }
        }
        printf("%s | len: %u\n", resume, header->len);
        return; // ne pas poursuivre les niveaux 2/3
    }

    //Niveau 2 et 3 
    if(verbosity >= 2) {
        printf("\nPaquet %d - %u octets capturés\n", packet_count, header->len);
        int indent = 0; //indentation pour l'affichage 
        int offset = 0; //offset pour l'analyse des protocoles
        uint16_t ethertype;

        //Analyse Ethernet
        offset = parse_ethernet(packet, header->len, verbosity, indent, &ethertype);
        indent += 2; // augmentation de l'indentation pour les prochaines couches

        //Analyse ARP (Layer 2, terminaison)
        if(ethertype == ETHERTYPE_ARP){
            parse_arp(packet + offset, header->len - offset, verbosity, indent);
        }
        //Analyse RARP (Layer 2, terminaison)
        else if(ethertype == ETHERTYPE_REVARP){
            parse_rarp(packet + offset, header->len - offset, verbosity, indent);
        }
        //Analyse IPv4 ou IPv6
        else if(ethertype == ETHERTYPE_IP){ //IPv4
            uint8_t proto;
            int ip_hdr_len = parse_ipv4(packet + offset, header->len - offset, verbosity, indent, &proto);
            if(ip_hdr_len == 0) {
                fprintf(stderr, "Erreur parsing IPv4, paquet ignoré\n");
            } else {
                offset += ip_hdr_len;
                indent += 2;
                //Analyse protocole transport
                //UDP
                if(proto == IPPROTO_UDP){
                    uint16_t src_port, dst_port;
                    int udp_len = parse_udp(packet + offset, header->len - offset, verbosity, indent, &src_port, &dst_port);
                    if(udp_len > 0) {
                        offset += udp_len;
                        indent += 2;
                        
                        app_proto_udp_t detected = detect_app_udp_v1(src_port, dst_port);
                        if(detected != APP_PROTO_UDP_NONE) {
                            int consumed = process_app_udp_v2v3(detected, packet + offset,
                                                                header->len - offset,
                                                                verbosity, indent, &offset);
                            if(consumed > 0) {
                                indent += 2;
                            }
                        }
                    }
                }
                //TCP
                else if(proto == IPPROTO_TCP){
                    uint16_t src_port, dst_port;
                    uint8_t flags;
                    int tcp_len = parse_tcp(packet + offset, header->len - offset, verbosity, indent, &src_port, &dst_port, &flags);
                    if(tcp_len > 0) {
                        offset += tcp_len;
                        indent += 2;
                        
                        app_proto_tcp_t detected = detect_app_tcp_v2v3(src_port, dst_port,
                                                                      packet + offset,
                                                                      header->len - offset);
                        if(detected != APP_PROTO_TCP_NONE) {
                            int consumed = process_app_tcp_v2v3(detected, packet + offset,
                                                                header->len - offset,
                                                                verbosity, indent, &offset);
                            if(consumed > 0) {
                                indent += 2;
                            }
                        }
                    }
                }
                //ICMP (IPv4)
                else if(proto == IPPROTO_ICMP){
                    int icmp_len = parse_icmp(packet + offset, header->len - offset, verbosity, indent);
                    if(icmp_len > 0) {
                        offset += icmp_len;
                        indent += 2;
                    }
                }
                //Hexdump pour verbosity 3
                if(verbosity == 3 && (unsigned int)offset < header->len) {
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("Data (%d bytes):\n", header->len - offset);
                    print_hexdump(packet + offset, header->len - offset);
                }
            }
        }
        else if (ethertype == ETHERTYPE_IPV6){
            uint8_t next_header;
            int ip6_hdr_len = parse_ipv6(packet + offset, header->len - offset, verbosity, indent, &next_header);
            if(ip6_hdr_len > 0) {
                offset += ip6_hdr_len;
                indent += 2;
                //Analyse protocole transport/ICMPv6
                //ICMPv6
                if(next_header == IPPROTO_ICMPV6){
                    int icmpv6_len = parse_icmpv6(packet + offset, header->len - offset, verbosity, indent);
                    if(icmpv6_len > 0) {
                        offset += icmpv6_len;
                        indent += 2;
                    }
                }
                //UDP
                else if(next_header == IPPROTO_UDP){
                    uint16_t src_port, dst_port;
                    int udp_len = parse_udp(packet + offset, header->len - offset, verbosity, indent, &src_port, &dst_port);
                    if(udp_len > 0) {
                        offset += udp_len;
                        indent += 2;
                        
                        app_proto_udp_t detected = detect_app_udp_v1(src_port, dst_port);
                        if(detected != APP_PROTO_UDP_NONE) {
                            int consumed = process_app_udp_v2v3(detected, packet + offset,
                                                                header->len - offset,
                                                                verbosity, indent, &offset);
                            if(consumed > 0) {
                                indent += 2;
                            }
                        }
                    }
                }
                //TCP
                else if(next_header == IPPROTO_TCP){
                    uint16_t src_port, dst_port;
                    uint8_t flags;
                    int tcp_len = parse_tcp(packet + offset, header->len - offset, verbosity, indent, &src_port, &dst_port, &flags);
                    if(tcp_len > 0) {
                        offset += tcp_len;
                        indent += 2;
                        
                        app_proto_tcp_t detected = detect_app_tcp_v2v3(src_port, dst_port,
                                                                      packet + offset,
                                                                      header->len - offset);
                        if(detected != APP_PROTO_TCP_NONE) {
                            int consumed = process_app_tcp_v2v3(detected, packet + offset,
                                                                header->len - offset,
                                                                verbosity, indent, &offset);
                            if(consumed > 0) {
                                indent += 2;
                            }
                        }
                    }
                }
                //Hexdump pour verbosity 3
                if(verbosity == 3 && (unsigned int)offset < header->len) {
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("Data (%d bytes):\n", header->len - offset);
                    print_hexdump(packet + offset, header->len - offset);
                }
            }
        }
    }
}