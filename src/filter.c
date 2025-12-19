/**

Module de gestion des filtres BPF (Berkeley Packet Filter)
 * 
 * Ce module fournit une interface simplifiée pour appliquer des filtres
 * de capture réseau via libpcap. Il supporte deux modes :
 * 
 * 1. Alias prédéfinis : Noms courts et mémorisables (dns, web, mail, etc.)
 *    convertis en expressions BPF complètes
 * 
 * 2. Expressions BPF brutes : Passées directement au compilateur pcap
 * 
 * Alias disponibles :
 * - dns     : Trafic DNS (TCP et UDP port 53)
 * - alldns  : Idem que dns
 * - http    : Trafic HTTP uniquement (TCP port 80)
 * - web     : Trafic web HTTP + HTTPS (TCP ports 80, 443)
 * - smtp    : Trafic SMTP (TCP ports 25, 587, 465)
 * - mail    : Tous les protocoles mail (SMTP, IMAP, POP3, variantes TLS)
 * - ftp     : Canal de contrôle FTP (TCP port 21)
 * - telnet  : Trafic Telnet (TCP port 23)
 * - all     : Pas de filtre (capturer tout)
 * 
 */

#include "filter.h"
#include <string.h>
#include <stdio.h>
#include "dns.h"  // Pour dns_bpf_all() - filtre DNS dynamique

/**
 * Traduit un alias utilisateur en expression BPF
 * 
 * Cette fonction prend en entrée soit un alias prédéfini (dns, web, mail, etc.)
 * soit une expression BPF brute, et retourne l'expression BPF correspondante.
 * 
 * Si l'entrée n'est pas reconnue comme alias, elle est retournée telle quelle
 * pour être traitée comme expression BPF directe.
 * 
 * @param user_expr Expression utilisateur (alias ou BPF)
 * 
 * @return Expression BPF correspondante (ne pas libérer)
 */
const char* filter_translate_alias(const char *user_expr) {
    if (!user_expr) return NULL;
    
    // Alias DNS
    /* Capture tout le trafic DNS (TCP et UDP port 53) */
    if (strcmp(user_expr, "dns") == 0 || strcmp(user_expr, "alldns") == 0) {
        return dns_bpf_all();
    }
    
    // Alias HTTP
    /* Trafic HTTP uniquement (port 80) */
    if (strcmp(user_expr, "http") == 0) {
        return "tcp port 80";
    }
    
    // Alias Web
    /* Trafic HTTP (80) et HTTPS (443) */
    if (strcmp(user_expr, "web") == 0) {
        return "(tcp port 80 or tcp port 443)";
    }
    
    // Alias SMTP
    /* Ports SMTP : 25 (relayage), 587 (soumission), 465 (TLS implicite) */
    if (strcmp(user_expr, "smtp") == 0) {
        return "(tcp port 25 or tcp port 587 or tcp port 465)";
    }
    
    // Alias Mail
    /* Tous les protocoles mail : SMTP (25, 587, 465), IMAP (143, 993), POP3 (110, 995) */
    if (strcmp(user_expr, "mail") == 0) {
        return "(tcp port 25 or tcp port 587 or tcp port 465 or tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995)";
    }
    
    // Alias FTP
    /* Canal de contrôle FTP (port 21)
     * Note: Le port 20 (données) et les ports passifs ne sont pas inclus */
    if (strcmp(user_expr, "ftp") == 0) {
        return "tcp port 21";
    }
    
    // Alias Telnet
    if (strcmp(user_expr, "telnet") == 0) {
        return "tcp port 23";
    }
    
    // Alias "all"
    /* Pas de filtrage (capturer tout le trafic) */
    if (strcmp(user_expr, "all") == 0) {
        return "";
    }
    
    // Expression non reconnue : retourner telle quelle (expression BPF brute)
    return user_expr;
}

/**
 * Compile et applique un filtre BPF à une session pcap
 * 
 * Cette fonction effectue les étapes suivantes :
 * 1. Traduit l'expression utilisateur (alias → BPF)
 * 2. Récupère les informations réseau de l'interface (si disponible)
 * 3. Compile le filtre BPF
 * 4. Applique le filtre à la session de capture
 * 
 * @param handle          Session pcap active
 * @param interface       Nom de l'interface (peut être NULL pour fichier)
 * @param user_expr       Expression utilisateur (alias ou BPF)
 * @param applied_expr_out Buffer pour stocker l'expression traduite (optionnel)
 * @param applied_expr_len Taille du buffer de sortie
 * 
 * @return FILTER_OK si succès, FILTER_ERR_COMPILE ou FILTER_ERR_SET sinon
 */
int filter_apply(pcap_t *handle,
                 const char *interface,
                 const char *user_expr,
                 char *applied_expr_out,
                 size_t applied_expr_len) {
    /* Pas de filtre demandé : rien à faire */
    if (!user_expr) {
        if (applied_expr_out && applied_expr_len) applied_expr_out[0] = '\0';
        return FILTER_OK;
    }

    /* Traduction de l'alias en expression BPF */
    const char *translated = filter_translate_alias(user_expr);
    if (applied_expr_out && applied_expr_len) {
        snprintf(applied_expr_out, applied_expr_len, "%s", translated);
    }

    /* Récupération des paramètres réseau de l'interface */
    struct bpf_program prog;
    bpf_u_int32 net = 0, mask = 0;
    if (interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Warning: lookupnet failed on %s: %s\n", interface, errbuf);
            net = 0; mask = 0;  /* Continuer malgré l'échec */
        }
    }

    /* Compilation du filtre BPF */
    if (pcap_compile(handle, &prog, translated, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter '%s': %s\n", translated, pcap_geterr(handle));
        return FILTER_ERR_COMPILE;
    }
    
    /* Application du filtre compilé */
    if (pcap_setfilter(handle, &prog) == -1) {
        fprintf(stderr, "Error applying filter '%s': %s\n", translated, pcap_geterr(handle));
        pcap_freecode(&prog);
        return FILTER_ERR_SET;
    }
    
    /* Libération de la structure compilée (le filtre reste actif) */
    pcap_freecode(&prog);
    return FILTER_OK;
}
