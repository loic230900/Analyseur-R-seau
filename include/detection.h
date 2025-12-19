/**
 * Ce fichier définit les énumérations et fonctions de détection des
 * protocoles de la couche 7 (application) basée sur l'analyse des ports.
 * 
 */

#ifndef DETECTION_H
#define DETECTION_H

#include <stdint.h>
#include <pcap.h>

/**
 * Cette énumération liste tous les protocoles de la couche application
 * que l'analyseur peut identifier sur des connexions TCP.
 */
typedef enum {
    APP_PROTO_TCP_NONE = 0,     // Aucun protocole reconnu 
    APP_PROTO_TCP_DNS,          // DNS sur TCP (port 53) 
    APP_PROTO_TCP_HTTP,         // HTTP (port 80) 
    APP_PROTO_TCP_HTTPS,        // HTTPS/TLS (port 443) 
    APP_PROTO_TCP_SMTP,         // SMTP (ports 25, 587) 
    APP_PROTO_TCP_SMTPS,        // SMTPS - TLS implicite (port 465)
    APP_PROTO_TCP_IMAP,         // IMAP (port 143)
    APP_PROTO_TCP_IMAPS,        // IMAPS - TLS implicite (port 993) 
    APP_PROTO_TCP_POP3,         // POP3 (port 110) 
    APP_PROTO_TCP_POP3S,        // POP3S - TLS implicite (port 995) 
    APP_PROTO_TCP_FTP,          // FTP canal de contrôle (port 21) 
    APP_PROTO_TCP_FTP_DATA,     // FTP canal de données (port 20) 
    APP_PROTO_TCP_TELNET        //Telnet (port 23) 
} app_proto_tcp_t;

/**
 * Cette énumération liste tous les protocoles de la couche application
 * que l'analyseur peut identifier sur des datagrammes UDP.
 */
typedef enum {
    APP_PROTO_UDP_NONE = 0,     // Aucun protocole reconnu 
    APP_PROTO_UDP_DNS,          // DNS sur UDP (port 53) 
    APP_PROTO_UDP_DHCP,         // DHCP (ports 67, 68) 
    APP_PROTO_UDP_QUIC          // QUIC/HTTP3 (port 443) uniqemetn detecte pour le bruit visuelle lors de captures 
} app_proto_udp_t;

// Constantes pour détection TLS 
#define TLS_RECORD_TYPE_HANDSHAKE 0x16  // Type de record TLS : Handshake 
#define TLS_VERSION_MAJOR         0x03  // Version majeure TLS (1.x) 
#define TLS_MIN_CHECK_LEN         5     // Octets minimum pour signature TLS

// FONCTIONS DE DÉTECTION
/**
 * Analyse les ports source/destination pour identifier le protocole
 * de la couche application.
 * 
 * @param src_port    Port source de la connexion
 * @param dst_port    Port destination de la connexion
 * @param payload_len Longueur du payload TCP disponible
 * 
 * @return Protocole détecté (app_proto_tcp_t) ou APP_PROTO_TCP_NONE si aucun
 */
app_proto_tcp_t detect_app_tcp(uint16_t src_port, uint16_t dst_port, int payload_len);

/**
 * Analyse les ports source/destination pour identifier le protocole
 * de la couche application.
 * 
 * @param src_port Port source du datagramme
 * @param dst_port Port destination du datagramme
 * 
 * @return Protocole détecté (app_proto_udp_t) ou APP_PROTO_UDP_NONE
 */
app_proto_udp_t detect_app_udp(uint16_t src_port, uint16_t dst_port);

/**
 * Retourne le nom du service TCP basé sur les ports (sans vérifier le payload).
 * Utilisé pour annoter les paquets de contrôle TCP (SYN, ACK, FIN) sans payload.
 * 
 * @param src_port Port source
 * @param dst_port Port destination
 * @return Nom du service (minuscules) ou NULL si inconnu
 */
const char* get_tcp_service_name(uint16_t src_port, uint16_t dst_port);

/**
 * Retourne le nom du service UDP basé sur les ports.
 * 
 * @param src_port Port source
 * @param dst_port Port destination
 * @return Nom du service (minuscules) ou NULL si inconnu
 */
const char* get_udp_service_name(uint16_t src_port, uint16_t dst_port);

#endif /* DETECTION_H */
