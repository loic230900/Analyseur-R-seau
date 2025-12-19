/**
 * Module de routage des protocoles applicatifs vers leurs parseurs
 */

#include <stdio.h>
#include <string.h>
#include "dispatch.h"
#include "detection.h"
#include "protocoles.h"
#include "util/safe_string.h"
#include "util/display_constants.h"

/**
 * Helper: affiche le statut TLS pour les protocoles chiffrés
 * 
 * @param proto_name  Nom du protocole (e.g., "HTTPS", "SMTPS")
 * @param packet      Pointeur vers le début du payload chiffré
 * @param length      Longueur du payload
 * @param verbosity   Niveau de verbosité (2 ou 3)
 * @param indent      Indentation pour l'affichage
 * @return void
 * 
 *  */
static void print_tls_status(const char *proto_name, const u_char *packet, int length, int verbosity, int indent) {
    // Vérifie si c'est une négociation TLS (handshake)
    int is_handshake = (length > TLS_MIN_CHECK_LEN && packet[0] == TLS_RECORD_TYPE_HANDSHAKE && packet[1] == TLS_VERSION_MAJOR);

    print_indent(indent);
    if (verbosity == 2) {
        printf("%s: %s\n", proto_name, is_handshake ? "TLS Negotiation" : "Encrypted data");
    } else if (verbosity == 3) {
        printf("[L7] %s Header:\n", proto_name);
        print_indent(indent + 2);
        if (is_handshake) {
            printf("Type: TLS Negotiation (Handshake)\n");
            print_indent(indent + 2);
            printf("Version: TLS 1.%d\n", packet[2]);
        } else {
            printf("Type: Encrypted Application Data\n");
            print_indent(indent + 2);
            printf("Length: %d bytes\n", length);
        }
    }
}

//  Dispatch vers les fonctions de résumé TCP (verbosité 1)

int process_app_tcp_v1(app_proto_tcp_t proto,
                       const u_char *packet, int caplen,
                       int tcp_payload_offset, char *resume,
                       uint16_t src_port, uint16_t dst_port,
                       const char *src_ip, const char *dst_ip) {
    int result = 0;
    
    switch(proto) {
        // DNS sur TCP 
        case APP_PROTO_TCP_DNS: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | DNS (TCP)");
            return dns_v1_summary(packet, caplen, tcp_payload_offset, resume, 1);
        }
        
        // HTTP (port 80)
        case APP_PROTO_TCP_HTTP:
            return http_v1_summary(packet, caplen, tcp_payload_offset, resume);
        
        // HTTPS (port 443)
        case APP_PROTO_TCP_HTTPS: {
            int payload_len = caplen - tcp_payload_offset;
            if (payload_len > 0) {
                const u_char *payload = packet + tcp_payload_offset;
                int is_hs = (payload_len > 5 && payload[0] == TLS_RECORD_TYPE_HANDSHAKE && payload[1] == TLS_VERSION_MAJOR);
                size_t len = strlen(resume);
                snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | HTTPS%s", is_hs ? " Handshake" : "");
            }
            result = 2;
            break;
        }
        
        // SMTP (ports 25, 587)
        case APP_PROTO_TCP_SMTP:
            return smtp_v1_summary(packet, caplen, tcp_payload_offset, resume);

        // SMTPS (port 465 - TLS implicite)
        case APP_PROTO_TCP_SMTPS: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | SMTPS (TLS)");
            result = 2;  // Code spécial pour ajouter les IPs
            break;
        }
        
        // IMAP (port 143)
        case APP_PROTO_TCP_IMAP:
            return imap_v1_summary(packet, caplen, tcp_payload_offset, resume);
        
        // IMAPS (port 993) 
        case APP_PROTO_TCP_IMAPS: {
            int imaps_result = imap_v1_summary(packet, caplen, tcp_payload_offset, resume);
            if(imaps_result) {
                char ip_info[128];
                snprintf(ip_info, sizeof(ip_info), " %s[%u] -> %s[%u]", src_ip, src_port, dst_ip, dst_port);
                safe_strcat(resume, ip_info, RESUME_BUFFER_SIZE);
            }
            return imaps_result;
        }
        
        // POP3 (port 110)
        case APP_PROTO_TCP_POP3:
            return pop3_v1_summary(packet, caplen, tcp_payload_offset, resume);
        
        // POP3S (port 995 - TLS implicite)
        case APP_PROTO_TCP_POP3S: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | POP3S (TLS)");
            result = 2;  // Code spécial pour ajouter les IPs
            break;
        }
        
        // FTP Control (port 21)
        case APP_PROTO_TCP_FTP:
            return ftp_v1_summary(packet, caplen, tcp_payload_offset, resume);
        
        // FTP Data (port 20)
        case APP_PROTO_TCP_FTP_DATA: {
            /* Affichage de la taille des données transférées */
            int data_len = caplen - tcp_payload_offset;
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | FTP-Data (%d bytes)", data_len);
            result = 2;  // Code spécial pour ajouter les IPs
            break;
        }
        
        // Telnet (port 23) 
        case APP_PROTO_TCP_TELNET:
            return telnet_v1_summary(packet, caplen, tcp_payload_offset, resume, src_port, dst_port);
            
        default:
            return 0;
    }
    
    /* Ajouter les IPs uniquement pour les protocoles chiffrés/opaques (result == 2) */
    if(result == 2) {
        char ip_info[128];
        snprintf(ip_info, sizeof(ip_info), " %s[%u] -> %s[%u]", src_ip, src_port, dst_ip, dst_port);
        safe_strcat(resume, ip_info, RESUME_BUFFER_SIZE);
    }
    
    return result ? 1 : 0;
}

/**
 * Dispatch vers les fonctions de résumé UDP (verbosité 1)
 * 
 * Cette fonction route le paquet vers la fonction *_v1_summary() appropriée
 * pour les protocoles UDP.
 * 
 * @param proto             Protocole détecté par detect_app_udp()
 * @param packet            Pointeur vers le paquet complet
 * @param caplen            Longueur totale capturée
 * @param udp_payload_offset Offset du début du payload UDP
 * @param resume            Buffer de sortie pour le résumé
 * @param src_port          Port source
 * @param dst_port          Port destination
 * @param src_ip            Adresse IP source (chaîne de caractères)
 * @param dst_ip            Adresse IP destination (chaîne de caractères)
 * 
 * @return 1 si traité, 0 sinon
 */
int process_app_udp_v1(app_proto_udp_t proto,
                       const u_char *packet, int caplen,
                       int udp_payload_offset, char *resume,
                       uint16_t src_port, uint16_t dst_port,
                       const char *src_ip, const char *dst_ip) {
    int result = 0;
    
    switch(proto) {
        // DNS sur UDP 
        case APP_PROTO_UDP_DNS: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | DNS");
            return dns_v1_summary(packet, caplen, udp_payload_offset, resume, 0);
        }
        
        // DHCP (ports 67/68)
        case APP_PROTO_UDP_DHCP: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | DHCP");
            return dhcp_v1_summary(packet, caplen, udp_payload_offset, resume);
        }
        
        // QUIC / HTTP/3 seulemetn detecte pour le bruit visuelle lors de captures
        case APP_PROTO_UDP_QUIC: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | QUIC");
            result = 2;  // Code spécial pour ajouter les IPs
            break;
        }
            
        default:
            return 0;
    }
    
    /* Ajouter les IPs uniquement pour les protocoles chiffrés/opaques (result == 2) */
    if(result == 2) {
        char ip_info[128];
        snprintf(ip_info, sizeof(ip_info), " %s[%u] -> %s[%u]", src_ip, src_port, dst_ip, dst_port);
        safe_strcat(resume, ip_info, RESUME_BUFFER_SIZE);
    }
    
    return result ? 1 : 0;
}

/**
 * Dispatch vers les parseurs TCP complets (verbosités 2-3)
 * 
 * Cette fonction route le paquet vers le parseur parse_*() approprié
 * pour un affichage détaillé multi-lignes.
 * 
 * @param proto     Protocole détecté par detect_app_tcp()
 * @param packet    Pointeur vers le payload TCP (après en-tête TCP)
 * @param length    Longueur du payload restant
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Niveau d'indentation pour l'affichage
 * @param offset    Pointeur vers l'offset courant (modifié si octets consommés)
 * @param src_port  Port source (pour Telnet)
 * @param dst_port  Port destination (pour Telnet)
 * 
 * @return Nombre d'octets consommés par le parseur
 */
int process_app_tcp_v2v3(app_proto_tcp_t proto,
                         const u_char *packet, int length,
                         int verbosity, int indent,
                         int *offset,
                         uint16_t src_port, uint16_t dst_port) {
    int consumed = 0;
    
    switch(proto) {
        // DNS sur TCP
        case APP_PROTO_TCP_DNS: {
            int is_resp;
            char qname[DNS_MAX_NAME_LEN];
            /* is_tcp=1 pour gérer le préfixe de longueur 2 octets */
            consumed = parse_dns(packet, length, verbosity, indent, 1, &is_resp, qname, sizeof(qname));
            break;
        }
        
        // HTTP (port 80)
        case APP_PROTO_TCP_HTTP:
            consumed = parse_http(packet, length, verbosity, indent);
            break;
        
        // HTTPS (port 443)
        case APP_PROTO_TCP_HTTPS:
            if (length > 0) print_tls_status("HTTPS", packet, length, verbosity, indent);
            consumed = 0;
            break;
        
        // SMTP (ports 25, 587)
        case APP_PROTO_TCP_SMTP:
            consumed = parse_smtp(packet, length, verbosity, indent);
            break;

        // SMTPS (port 465)
        case APP_PROTO_TCP_SMTPS:
            consumed = parse_smtp(packet, length, verbosity, indent);
            if (consumed == 0 && length > 0) {
                print_tls_status("SMTPS", packet, length, verbosity, indent);
            }
            break;
        
        // IMAP (port 143)
        case APP_PROTO_TCP_IMAP:
            consumed = parse_imap(packet, length, verbosity, indent);
            break;
        
        // IMAPS (port 993)
        case APP_PROTO_TCP_IMAPS:
            if (length > 0) print_tls_status("IMAPS", packet, length, verbosity, indent);
            consumed = 0;
            break;
        
        // POP3 (port 110)
        case APP_PROTO_TCP_POP3:
            consumed = parse_pop3(packet, length, verbosity, indent);
            break;
        
        // POP3S (port 995)
        case APP_PROTO_TCP_POP3S:
            consumed = parse_pop3(packet, length, verbosity, indent);
            if (consumed == 0 && length > 0) {
                print_tls_status("POP3S", packet, length, verbosity, indent);
            }
            break;
        
        // FTP Control (port 21)
        case APP_PROTO_TCP_FTP:
            consumed = parse_ftp(packet, length, verbosity, indent);
            break;
        
        // FTP Data (port 20)
        case APP_PROTO_TCP_FTP_DATA:
            consumed = parse_ftp_data(packet, length, verbosity, indent);
            break;
        
        // Telnet (port 23)
        case APP_PROTO_TCP_TELNET:
            consumed = parse_telnet(packet, length, verbosity, indent, src_port, dst_port);
            break;
            
        default:
            consumed = 0;
            break;
    }
    
    /* Mise à jour de l'offset si des octets ont été consommés */
    if(consumed > 0 && offset != NULL) {
        *offset += consumed;
    }
    
    return consumed;
}

/**
 * Dispatch vers les parseurs UDP complets (verbosités 2-3)
 * 
 * Cette fonction route le paquet vers le parseur parse_*() approprié
 * pour un affichage détaillé multi-lignes.
 * 
 * @param proto     Protocole détecté par detect_app_udp()
 * @param packet    Pointeur vers le payload UDP (après en-tête UDP)
 * @param length    Longueur du payload restant
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Niveau d'indentation pour l'affichage
 * @param offset    Pointeur vers l'offset courant (modifié si octets consommés)
 * 
 * @return Nombre d'octets consommés par le parseur
 */
int process_app_udp_v2v3(app_proto_udp_t proto,
                         const u_char *packet, int length,
                         int verbosity, int indent,
                         int *offset) {
    int consumed = 0;
    
    switch(proto) {
        // DNS sur UDP
        case APP_PROTO_UDP_DNS: {
            int is_resp;
            char qname[DNS_MAX_NAME_LEN];
            /* is_tcp=0 pour format UDP (pas de préfixe de longueur) */
            consumed = parse_dns(packet, length, verbosity, indent, 0, &is_resp, qname, sizeof(qname));
            break;
        }
        
        // DHCP (ports 67/68)
        case APP_PROTO_UDP_DHCP:
            consumed = parse_dhcp(packet, length, verbosity, indent);
            break;
        
        // QUIC / HTTP/3 (port 443) parsing minimaliste
        case APP_PROTO_UDP_QUIC:
            print_indent(indent);
            if(verbosity == 2) {
                printf("QUIC: HTTP/3 (%d bytes)\n", length);
            } else if(verbosity == 3) {
                printf("QUIC Header:\n");
                print_indent(indent+2);
                printf("Protocol: HTTP/3 over UDP\n");
                print_indent(indent+2);
                printf("Payload: %d bytes (encrypted)\n", length);
                /* Analyse du premier octet pour déterminer le type d'en-tête */
                if(length > 0) {
                    uint8_t first_byte = packet[0];
                    print_indent(indent+2);
                    if(first_byte & 0x80) {
                        printf("Header Type: Long (initial connection)\n");
                    } else {
                        printf("Header Type: Short (established connection)\n");
                    }
                }
            }
            consumed = 0;  /* Contenu QUIC chiffré, pas de parsing */
            break;
            
        default:
            consumed = 0;
            break;
    }
    
    /* Mise à jour de l'offset si des octets ont été consommés */
    if(consumed > 0 && offset != NULL) {
        *offset += consumed;
    }
    
    return consumed;
}
