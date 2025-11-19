#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "capture.h"
#include "hexdump.h"
#include "protocoles/protocoles.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    capture_args_t *capture = (capture_args_t *)args;
    int verbosity = capture->verbosity;
    static int packet_count = 0;
    packet_count++;

    //Déterminer le type de paquet pour affichage niveau 1
    const struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ethertype = ntohs(eth_header->ether_type);
    int offset = 14;
    char resume[256] = "";

    //Niveau 1: affichage très concis
    if (verbosity == 1) {
        if(ethertype == ETHERTYPE_ARP){ //ARP
            strcat(resume, "ARP");
            arp_v1_summary(packet, header->caplen, 14, resume); //ajout who-has / is-at 
        } 
        else if(ethertype == ETHERTYPE_IP){ //IPv4
            strcat(resume, "IPv4");
            if(header->caplen >= 14 + (int)sizeof(struct iphdr)){
                //calcul de l'offset de la couche 4
                const struct iphdr *ip = (const struct iphdr *)(packet + 14);
                int ihl = ip->ihl * 4;
                if(header->caplen >= 14 + ihl){
                    int l4off = 14 + ihl;
                    if(ip->protocol == IPPROTO_ICMP){ //ICMP
                        strcat(resume, " | ICMP");
                        icmp_v1_summary(packet, header->caplen, l4off, resume);
                    } 
                    else if(ip->protocol == IPPROTO_TCP){ //TCP
                        strcat(resume, " | TCP");
                        tcp_v1_flags_summary(packet, header->caplen, l4off, resume);
                        // Applications courantes
                        if(header->caplen >= l4off + (int)sizeof(struct tcphdr)){
                            const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4off);
                            uint16_t sp = ntohs(tcp->source), dp = ntohs(tcp->dest);
                            // DNS
                            if(sp == 53 || dp == 53){
                                strcat(resume, " | DNS");
                                dns_v1_summary(packet, header->caplen, l4off + tcp->doff*4, resume);
                            }
                            else if(sp == 80 || dp == 80) strcat(resume, " | HTTP");
                        }
                    } 
                    else if(ip->protocol == IPPROTO_UDP){ //UDP
                        strcat(resume, " | UDP");
                        // Applications courantes
                        if(header->caplen >= l4off + (int)sizeof(struct udphdr)){
                            const struct udphdr *udp = (const struct udphdr *)(packet + l4off);
                            uint16_t sp = ntohs(udp->source), dp = ntohs(udp->dest);
                            int udp_payload_off = l4off + 8;
                            int app_done = 0;
                            // DNS  
                            if(sp == 53 || dp == 53){
                                strcat(resume, " | DNS");
                                dns_v1_summary(packet, header->caplen, udp_payload_off, resume);
                                app_done = 1;
                            }
                            // DHCP
                            if(sp == 67 || sp == 68 || dp == 67 || dp == 68){
                                strcat(resume, " | DHCP");
                                dhcp_v1_summary(packet, header->caplen, udp_payload_off, resume);
                                app_done = 1;
                            }
                            if(!app_done){ // ports génériques si pas d'application reconnue
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
                    if(header->caplen >= l4off + (int)sizeof(struct tcphdr)){
                        const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4off);
                        uint16_t sp = ntohs(tcp->source), dp = ntohs(tcp->dest);
                        // DNS
                        if(sp == 53 || dp == 53){ 
                            strcat(resume, " | DNS");
                            dns_v1_summary(packet, header->caplen, l4off + tcp->doff*4, resume);
                        }
                        if(sp == 80 || dp == 80) strcat(resume, " | HTTP");
                    }
                } 
                else if(nxt == IPPROTO_UDP){ //UDP
                    strcat(resume, " | UDP");
                    // Applications courantes
                    if(header->caplen >= l4off + (int)sizeof(struct udphdr)){
                        const struct udphdr *udp = (const struct udphdr *)(packet + l4off);
                        uint16_t sp = ntohs(udp->source), dp = ntohs(udp->dest);
                        int udp_payload_off = l4off + 8; // taille en-tête UDP = 8 octets
                        int app_done = 0; //indicateur application reconnue
                        // DNS
                        if(sp == 53 || dp == 53){
                            strcat(resume, " | DNS");
                            dns_v1_summary(packet, header->caplen, udp_payload_off, resume);
                            app_done = 1;
                        }
                        // DHCP
                        if(sp == 67 || sp == 68 || dp == 67 || dp == 68){
                            strcat(resume, " | DHCP");
                            dhcp_v1_summary(packet, header->caplen, udp_payload_off, resume);
                            app_done = 1;
                        }
                        if(!app_done){ // ports génériques si pas d'application reconnue
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
                        // DNS over UDP
                        if (src_port == 53 || dst_port == 53) {
                            int is_resp; char qname[DNS_MAX_NAME_LEN];
                            int dns_consumed = parse_dns(packet + offset, header->len - offset, verbosity, indent, 0, &is_resp, qname, sizeof(qname));
                            if (dns_consumed > 0) {
                                offset += dns_consumed;
                                indent += 2;
                            }
                        }
                        //BOOTP/DHCP
                        if (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68){
                            parse_dhcp(packet + offset, header->len - offset, verbosity, indent);
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
                        /* DNS over TCP */
                        if (src_port == 53 || dst_port == 53) {
                            int is_resp; char qname[DNS_MAX_NAME_LEN];
                            int dns_consumed = parse_dns(packet + offset, header->len - offset, verbosity, indent, 1, &is_resp, qname, sizeof(qname));
                            if (dns_consumed > 0) {
                                offset += dns_consumed;
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
                        /* DNS over UDP (IPv6) */
                        if (src_port == 53 || dst_port == 53) {
                            int is_resp; char qname[DNS_MAX_NAME_LEN];
                            int dns_consumed = parse_dns(packet + offset, header->len - offset, verbosity, indent, 0, &is_resp, qname, sizeof(qname));
                            if (dns_consumed > 0) {
                                offset += dns_consumed;
                                indent += 2;
                            }
                        }
                        //BOOTP/DHCP
                        if (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68){
                            parse_dhcp(packet + offset, header->len - offset, verbosity, indent);
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
                        /* DNS over TCP (IPv6) */
                        if (src_port == 53 || dst_port == 53) {
                            int is_resp; char qname[DNS_MAX_NAME_LEN];
                            int dns_consumed = parse_dns(packet + offset, header->len - offset, verbosity, indent, 1, &is_resp, qname, sizeof(qname));
                            if (dns_consumed > 0) {
                                offset += dns_consumed;
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