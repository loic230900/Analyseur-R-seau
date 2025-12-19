/**
 * @file detection.c
 * @brief Module de détection des protocoles applicatifs
 * 
 * Ce module implémente la logique de détection des protocoles de la couche
 * application (couche 7 OSI) basée sur l'analyse des ports source et destination.
 * 
 * Deux systèmes de détection distincts :
 * - detect_app_tcp() : Protocoles TCP (HTTP, HTTPS, SMTP, IMAP, POP3, FTP, etc.)
 * - detect_app_udp() : Protocoles UDP (DNS, DHCP, QUIC)
 * 
 * Les détections sont ordonnées par priorité pour éviter les ambiguïtés.
 * Pour certains protocoles (POP3S), une vérification de la signature TLS
 * peut être effectuée pour différencier le trafic chiffré du trafic clair.
 * 
 * @author Projet Services Réseaux M1 SIRIS
 * @date 2024-2025
 */

#include "detection.h"
#include "capture.h"
#include "../protocoles/include/dhcp.h"
#include "../protocoles/include/http.h"
#include "protocoles.h"

/* ============================================================================
 * DÉTECTION DES PROTOCOLES APPLICATIFS TCP
 * ============================================================================ */

/**
 * @brief Détecte le protocole applicatif d'une connexion TCP
 * 
 * Cette fonction analyse les ports source et destination pour identifier
 * le protocole applicatif transporté. Les protocoles sont testés par
 * ordre de priorité décroissante.
 * 
 * Protocoles détectés :
 * - DNS (port 53) : Requêtes DNS sur TCP
 * - HTTP (port 80) : Trafic web non chiffré
 * - HTTPS (port 443) : Trafic web chiffré TLS
 * - SMTP (ports 25, 587) : Envoi de mail en clair
 * - SMTPS (port 465) : Envoi de mail chiffré (TLS implicite)
 * - IMAP (port 143) : Récupération mail en clair
 * - IMAPS (port 993) : Récupération mail chiffrée
 * - POP3 (port 110) : Récupération mail en clair
 * - POP3S (port 995) : Récupération mail chiffrée
 * - FTP (port 21) : Canal de contrôle FTP
 * - FTP-DATA (port 20) : Canal de données FTP (mode actif)
 * - Telnet (port 23) : Administration à distance
 * 
 * @param src_port       Port source de la connexion TCP
 * @param dst_port       Port destination de la connexion TCP
 * @param payload_len    Longueur du payload TCP (0 = pas d'analyse TLS)
 * @param payload_start  Pointeur vers le début du payload (pour détection TLS)
 * @param check_tls      Activer la vérification de signature TLS (1) ou non (0)
 * 
 * @return Enum app_proto_tcp_t identifiant le protocole, ou APP_PROTO_TCP_NONE
 */
app_proto_tcp_t detect_app_tcp(uint16_t src_port, uint16_t dst_port,
                                int payload_len,
                                const u_char *payload_start,
                                int check_tls) {
    /* Ces paramètres sont conservés pour compatibilité API avec d'autres protocoles
     * qui pourraient nécessiter une inspection du payload (ex: détection TLS) */
    (void)payload_start;
    (void)check_tls;
    
    /* Retour anticipé si aucun payload à analyser */
    if(payload_len <= 0) {
        return APP_PROTO_TCP_NONE;
    }
    
    /* ========== DNS (priorité 1) - Port 53 ========== */
    if(src_port == DNS_PORT || dst_port == DNS_PORT) {
        return APP_PROTO_TCP_DNS;
    }
    
    /* ========== HTTP (priorité 2) - Port 80 ========== */
    if(src_port == HTTP_PORT_PLAIN || dst_port == HTTP_PORT_PLAIN) {
        return APP_PROTO_TCP_HTTP;
    }
    
    /* ========== HTTPS (priorité 3) - Port 443 ========== */
    if(src_port == HTTPS_PORT || dst_port == HTTPS_PORT) {
        return APP_PROTO_TCP_HTTPS;
    }
    
    /* ========== SMTP (priorité 4) - Ports 25, 587 ========== */
    /* Port 25 : MTA vers MTA (relayage)
     * Port 587 : MUA vers MSA (soumission avec STARTTLS possible) */
    if((src_port == SMTP_PORT_PLAIN || dst_port == SMTP_PORT_PLAIN) ||
       (src_port == SMTP_PORT_SUBMISSION || dst_port == SMTP_PORT_SUBMISSION)) {
        return APP_PROTO_TCP_SMTP;
    }

    /* ========== SMTPS (priorité 4bis) - Port 465 ========== */
    /* TLS implicite : connexion chiffrée dès l'établissement
     * Contrairement à STARTTLS (port 587) qui démarre en clair */
    if(src_port == SMTP_PORT_SSL || dst_port == SMTP_PORT_SSL) {
        return APP_PROTO_TCP_SMTPS;
    }
    
    /* ========== IMAP (priorité 5) - Port 143 ========== */
    if(src_port == IMAP_PORT_PLAIN || dst_port == IMAP_PORT_PLAIN) {
        return APP_PROTO_TCP_IMAP;
    }
    
    /* ========== IMAPS (priorité 6) - Port 993 ========== */
    if(src_port == IMAP_PORT_SSL || dst_port == IMAP_PORT_SSL) {
        return APP_PROTO_TCP_IMAPS;
    }
    
    /* ========== POP3 (priorité 7) - Port 110 ========== */
    if(src_port == POP3_PORT_PLAIN || dst_port == POP3_PORT_PLAIN) {
        return APP_PROTO_TCP_POP3;
    }
    
    /* ========== POP3S (priorité 8) - Port 995 ========== */
    /* Port 995 est exclusivement POP3S (TLS implicite)
     * Contrairement à STARTTLS qui démarre en clair sur port 110 */
    if(src_port == POP3_PORT_SSL || dst_port == POP3_PORT_SSL) {
        return APP_PROTO_TCP_POP3S;
    }
    
    /* ========== FTP Control (priorité 9) - Port 21 ========== */
    /* Canal de commandes/réponses textuelles */
    if(src_port == FTP_PORT_CONTROL || dst_port == FTP_PORT_CONTROL) {
        return APP_PROTO_TCP_FTP;
    }
    
    /* ========== FTP Data (priorité 9bis) - Port 20 ========== */
    /* Canal de transfert de fichiers (mode actif uniquement)
     * Note: Le mode passif utilise des ports éphémères non détectables
     * sans analyse de l'état de la connexion FTP */
    if(src_port == FTP_PORT_DATA || dst_port == FTP_PORT_DATA) {
        return APP_PROTO_TCP_FTP_DATA;
    }
    
    /* ========== Telnet (priorité 10) - Port 23 ========== */
    if(src_port == TELNET_PORT || dst_port == TELNET_PORT) {
        return APP_PROTO_TCP_TELNET;
    }
    
    /* Aucun protocole applicatif reconnu */
    return APP_PROTO_TCP_NONE;
}

/* ============================================================================
 * DÉTECTION DES PROTOCOLES APPLICATIFS UDP
 * ============================================================================ */

/**
 * @brief Détecte le protocole applicatif d'un datagramme UDP
 * 
 * Cette fonction analyse les ports source et destination pour identifier
 * le protocole applicatif transporté sur UDP.
 * 
 * Protocoles détectés :
 * - DNS (port 53) : Requêtes DNS standard
 * - mDNS (port 5353) : Multicast DNS (découverte locale)
 * - DHCP (ports 67, 68) : Configuration IP automatique
 * - QUIC (port 443) : HTTP/3 sur UDP
 * 
 * @param src_port Port source du datagramme UDP
 * @param dst_port Port destination du datagramme UDP
 * 
 * @return Enum app_proto_udp_t identifiant le protocole, ou APP_PROTO_UDP_NONE
 */
app_proto_udp_t detect_app_udp(uint16_t src_port, uint16_t dst_port) {
    /* ========== DNS (priorité 1) - Port 53 ========== */
    if(src_port == DNS_PORT || dst_port == DNS_PORT) {
        return APP_PROTO_UDP_DNS;
    }
    
    /* ========== mDNS (priorité 2) - Port 5353 ========== */
    /* Multicast DNS pour découverte de services locaux (.local)
     * Utilise le même format que DNS standard */
    if(src_port == 5353 || dst_port == 5353) {
        return APP_PROTO_UDP_DNS;  /* Réutilise le parser DNS */
    }
    
    /* ========== DHCP (priorité 3) - Ports 67/68 ========== */
    /* Port 67 : Serveur DHCP (BOOTP server)
     * Port 68 : Client DHCP (BOOTP client) */
    if(src_port == DHCP_SERVER_PORT || src_port == DHCP_CLIENT_PORT ||
       dst_port == DHCP_SERVER_PORT || dst_port == DHCP_CLIENT_PORT) {
        return APP_PROTO_UDP_DHCP;
    }
    
    /* ========== QUIC / HTTP/3 (priorité 4) - Port 443 ========== */
    /* Protocole QUIC développé par Google, base de HTTP/3
     * Entièrement chiffré, seuls les en-têtes publics sont lisibles */
    if(src_port == HTTPS_PORT || dst_port == HTTPS_PORT) {
        return APP_PROTO_UDP_QUIC;
    }
    
    /* Aucun protocole applicatif reconnu */
    return APP_PROTO_UDP_NONE;
}
