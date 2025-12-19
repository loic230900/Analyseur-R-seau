/**

Module de routage des protocoles applicatifs vers leurs parseurs
 * 
 * Ce module fait le lien entre la détection des protocoles (detection.c)
 * et les parseurs individuels (protocoles/). Il implémente quatre
 * fonctions de dispatch selon le niveau de verbosité et le transport :
 * 
 * Verbosité 1 (format concis, une ligne) :
 * - process_app_tcp_v1() : TCP → *_v1_summary()
 * - process_app_udp_v1() : UDP → *_v1_summary()
 * 
 * Verbosités 2-3 (format détaillé, multi-lignes) :
 * - process_app_tcp_v2v3() : TCP → parse_*()
 * - process_app_udp_v2v3() : UDP → parse_*()
 * 
 * Pour les protocoles chiffrés (HTTPS, SMTPS, IMAPS, POP3S, QUIC),
 * seuls les en-têtes TLS sont analysés, le contenu reste opaque.
 * 
 */

#include <stdio.h>
#include <string.h>
#include "dispatch.h"
#include "detection.h"
#include "protocoles.h"
#include "util/safe_string.h"
#include "util/display_constants.h"

/**
 * Dispatch vers les fonctions de résumé TCP (verbosité 1)
 * 
 * Cette fonction route le paquet vers la fonction *_v1_summary() appropriée
 * en fonction du protocole détecté. Le résultat est ajouté au buffer resume.
 * 
 * Protocoles gérés :
 * - DNS/TCP : Affiche le nom de domaine interrogé
 * - HTTP : Affiche la méthode et l'URL ou le code de réponse
 * - HTTPS : Affiche "Handshake" ou "Encrypted"
 * - SMTP : Affiche la commande ou le code de réponse
 * - SMTPS : Affiche "(TLS)" - contenu chiffré
 * - IMAP/IMAPS : Affiche la commande ou réponse
 * - POP3 : Affiche la commande ou réponse
 * - POP3S : Affiche "(TLS)" - contenu chiffré
 * - FTP : Affiche la commande ou réponse
 * - FTP-Data : Affiche la taille des données transférées
 * - Telnet : Affiche le type de données (commande/texte)
 * 
 * @param proto             Protocole détecté par detect_app_tcp()
 * @param packet            Pointeur vers le paquet complet
 * @param caplen            Longueur totale capturée
 * @param tcp_payload_offset Offset du début du payload TCP
 * @param resume            Buffer de sortie pour le résumé
 * @param src_port          Port source (pour Telnet)
 * @param dst_port          Port destination (pour Telnet)
 * 
 * @return 1 si traité, 0 sinon
 */
int process_app_tcp_v1(app_proto_tcp_t proto,
                       const u_char *packet, int caplen,
                       int tcp_payload_offset, char *resume,
                       uint16_t src_port, uint16_t dst_port) {
    switch(proto) {
        // DNS sur TCP
        case APP_PROTO_TCP_DNS: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | DNS");
            return dns_v1_summary(packet, caplen, tcp_payload_offset, resume, 1);
        }
        
        // HTTP (port 80)
        case APP_PROTO_TCP_HTTP:
            return http_v1_summary(packet, caplen, tcp_payload_offset, resume);
        
        // HTTPS (port 443)
        case APP_PROTO_TCP_HTTPS: {
            const u_char *payload = packet + tcp_payload_offset;
            int payload_len = caplen - tcp_payload_offset;
            size_t len = strlen(resume);
            /* Détection du handshake TLS vs données chiffrées */
            if(payload_len > 5 && payload[0] == TLS_RECORD_TYPE_HANDSHAKE && payload[1] == TLS_VERSION_MAJOR) {
                snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | HTTPS Handshake");
            } else if(payload_len > 0) {
                snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | HTTPS");
            }
            return 1;
        }
        
        // SMTP (ports 25, 587)
        case APP_PROTO_TCP_SMTP:
            return smtp_v1_summary(packet, caplen, tcp_payload_offset, resume);

        // SMTPS (port 465 - TLS implicite)
        case APP_PROTO_TCP_SMTPS: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | SMTPS (TLS)");
            return 1;
        }
        
        // IMAP (port 143)
        case APP_PROTO_TCP_IMAP:
            return imap_v1_summary(packet, caplen, tcp_payload_offset, resume);
        
        // IMAPS (port 993)
        case APP_PROTO_TCP_IMAPS:
            return imap_v1_summary(packet, caplen, tcp_payload_offset, resume);
        
        // POP3 (port 110)
        case APP_PROTO_TCP_POP3:
            return pop3_v1_summary(packet, caplen, tcp_payload_offset, resume);
        
        // POP3S (port 995 - TLS implicite)
        case APP_PROTO_TCP_POP3S: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | POP3S (TLS)");
            return 1;
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
            return 1;
        }
        
        // Telnet (port 23)
        case APP_PROTO_TCP_TELNET:
            return telnet_v1_summary(packet, caplen, tcp_payload_offset, resume, src_port, dst_port);
            
        default:
            return 0;
    }
}

/**
 * Dispatch vers les fonctions de résumé UDP (verbosité 1)
 * 
 * Cette fonction route le paquet vers la fonction *_v1_summary() appropriée
 * pour les protocoles UDP.
 * 
 * Protocoles gérés :
 * - DNS : Affiche le nom de domaine interrogé
 * - DHCP : Affiche le type de message (Discover, Offer, etc.)
 * - QUIC : Affiche "QUIC" (contenu chiffré)
 * 
 * @param proto             Protocole détecté par detect_app_udp()
 * @param packet            Pointeur vers le paquet complet
 * @param caplen            Longueur totale capturée
 * @param udp_payload_offset Offset du début du payload UDP
 * @param resume            Buffer de sortie pour le résumé
 * 
 * @return 1 si traité, 0 sinon
 */
int process_app_udp_v1(app_proto_udp_t proto,
                       const u_char *packet, int caplen,
                       int udp_payload_offset, char *resume) {
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
        
        // QUIC / HTTP/3
        case APP_PROTO_UDP_QUIC: {
            size_t len = strlen(resume);
            snprintf(resume + len, RESUME_BUFFER_SIZE - len, " | QUIC");
            return 1;  /* Contenu chiffré, pas d'analyse supplémentaire */
        }
            
        default:
            return 0;
    }
}

/**
 * Dispatch vers les parseurs TCP complets (verbosités 2-3)
 * 
 * Cette fonction route le paquet vers le parseur parse_*() approprié
 * pour un affichage détaillé multi-lignes.
 * 
 * Gestion des protocoles chiffrés :
 * - HTTPS : Affiche le type TLS (Handshake/Data) sans parser le contenu
 * - SMTPS : Tente le parse SMTP, sinon affiche "chiffré"
 * - IMAPS : Affiche le statut TLS sans parser
 * - POP3S : Tente le parse POP3, sinon affiche "chiffré"
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
            /* Détection du type de segment TLS */
            if(length > TLS_MIN_CHECK_LEN && packet[0] == TLS_RECORD_TYPE_HANDSHAKE && packet[1] == TLS_VERSION_MAJOR) {
                print_indent(indent);
                if(verbosity == 2) {
                    printf("HTTPS: TLS Negotiation\n");
                } else if(verbosity == 3) {
                    printf("[L7] HTTPS Header:\n");
                    print_indent(indent+2);
                    printf("Type: TLS Negotiation (Handshake)\n");
                    print_indent(indent+2);
                    printf("Version: TLS 1.%d\n", packet[2]);
                }
                consumed = 0;  /* Pas de parsing du contenu chiffré */
            } else if(length > 0) {
                print_indent(indent);
                if(verbosity == 2) {
                    printf("HTTPS: Encrypted data (%d bytes)\n", length);
                } else if(verbosity == 3) {
                    printf("[L7] HTTPS Header:\n");
                    print_indent(indent+2);
                    printf("Type: Encrypted Application Data\n");
                    print_indent(indent+2);
                    printf("Length: %d bytes\n", length);
                }
                consumed = 0;
            }
            break;
        
        // SMTP (ports 25, 587)
        case APP_PROTO_TCP_SMTP:
            consumed = parse_smtp(packet, length, verbosity, indent);
            break;

        // SMTPS (port 465)
        case APP_PROTO_TCP_SMTPS:
            if(length > TLS_MIN_CHECK_LEN && packet[0] == TLS_RECORD_TYPE_HANDSHAKE && packet[1] == TLS_VERSION_MAJOR) {
                print_indent(indent);
                printf("SMTPS (TLS Negotiation) - content not parsed\n");
                consumed = 0;
            } else {
                /* Tenter le parsing SMTP en cas de STARTTLS incomplet */
                consumed = parse_smtp(packet, length, verbosity, indent);
                if(consumed == 0) {
                    print_indent(indent);
                    printf("SMTPS (Encrypted or non-handshake segment)\n");
                }
            }
            break;
        
        // IMAP (port 143)
        case APP_PROTO_TCP_IMAP:
            consumed = parse_imap(packet, length, verbosity, indent);
            break;
        
        // IMAPS (port 993)
        case APP_PROTO_TCP_IMAPS:
            if(length > TLS_MIN_CHECK_LEN) {
                if(packet[0] == TLS_RECORD_TYPE_HANDSHAKE && packet[1] == TLS_VERSION_MAJOR) {
                    print_indent(indent);
                    printf("IMAPS (TLS Negotiation) - content not parsed\n");
                    consumed = 0;
                } else {
                    print_indent(indent);
                    printf("IMAPS (Encrypted or non-handshake segment)\n");
                    consumed = 0;
                }
            }
            break;
        
        // POP3 (port 110)
        case APP_PROTO_TCP_POP3:
            consumed = parse_pop3(packet, length, verbosity, indent);
            break;
        
        // POP3S (port 995)
        case APP_PROTO_TCP_POP3S:
            if(length > TLS_MIN_CHECK_LEN) {
                if(packet[0] == TLS_RECORD_TYPE_HANDSHAKE && packet[1] == TLS_VERSION_MAJOR) {
                    print_indent(indent);
                    printf("POP3S (TLS Negotiation) - content not parsed\n");
                    consumed = 0;
                } else {
                    /* Tenter le parsing POP3 en cas de STARTTLS incomplet */
                    consumed = parse_pop3(packet, length, verbosity, indent);
                    if(consumed == 0) {
                        print_indent(indent);
                        printf("POP3S (Encrypted or non-handshake segment)\n");
                    }
                }
            }
            break;
        
        // FTP Control (port 21)
        case APP_PROTO_TCP_FTP:
            consumed = parse_ftp(packet, length, verbosity, indent);
            break;
        
        // FTP Data (port 20)
        case APP_PROTO_TCP_FTP_DATA:
            /* Canal de données FTP : affichage du transfert */
            print_indent(indent);
            if(verbosity == 2) {
                printf("FTP-Data: %d bytes transferred\n", length);
            } else if(verbosity == 3) {
                printf("[L7] FTP Data Transfer:\n");
                print_indent(indent + 2);
                printf("Type: File/Directory data\n");
                print_indent(indent + 2);
                printf("Size: %d bytes\n", length);
                /* Aperçu du contenu si c'est du texte (listing de répertoire) */
                if(length > 0 && length < 1024) {
                    int is_text = 1;
                    for(int i = 0; i < length && i < 100; i++) {
                        if(packet[i] < 32 && packet[i] != '\r' && packet[i] != '\n' && packet[i] != '\t') {
                            is_text = 0;
                            break;
                        }
                    }
                    if(is_text) {
                        print_indent(indent + 2);
                        printf("Content (text preview):\n");
                        print_indent(indent + 2);
                        printf("---\n");
                        fwrite(packet, 1, (size_t)(length < 512 ? length : 512), stdout);
                        if(length > 512) printf("\n... (truncated)");
                        printf("\n");
                        print_indent(indent + 2);
                        printf("---\n");
                    }
                }
            }
            consumed = length;  /* Consommer tout le payload */
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
        
        // QUIC / HTTP/3 (port 443)
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
