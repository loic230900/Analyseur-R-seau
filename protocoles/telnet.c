#include "telnet.h"
#include "../util/textutils.h"
#include "../hexdump.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/**
 * Vérifie si un octet est une commande Telnet valide (240-255)
 * Approche générique : détecte toute commande Telnet selon RFC 854
 */
static int is_telnet_command_byte(unsigned char byte) {
    return (byte >= 240); // 240-255 sont les commandes Telnet (byte est unsigned char, donc <= 255 toujours vrai)
}

/**
 * Obtient le nom d'une commande Telnet de manière générique
 * Approche générique : construit le nom à partir de la valeur
 */
static void telnet_command_name(unsigned char cmd, char *buf, int buf_len) {
    // Commandes courantes avec noms spécifiques
    switch(cmd) {
        case 255: snprintf(buf, buf_len, "IAC"); return;
        case 254: snprintf(buf, buf_len, "DONT"); return;
        case 253: snprintf(buf, buf_len, "DO"); return;
        case 252: snprintf(buf, buf_len, "WONT"); return;
        case 251: snprintf(buf, buf_len, "WILL"); return;
        case 250: snprintf(buf, buf_len, "SB"); return;
        case 240: snprintf(buf, buf_len, "SE"); return;
        default:
            // Pour les autres, afficher la valeur hex
            snprintf(buf, buf_len, "CMD_0x%02X", cmd);
            return;
    }
}

/**
 * Vérifie si une commande nécessite un paramètre (option)
 * Approche générique : WILL, WONT, DO, DONT nécessitent une option
 */
static int telnet_command_needs_option(unsigned char cmd) {
    return (cmd == 251 || cmd == 252 || cmd == 253 || cmd == 254); // WILL, WONT, DO, DONT
}

/**
 * Parse une commande Telnet (IAC + commande + optionnellement option)
 * Approche générique : détecte et parse sans liste exhaustive
 * @return nombre d'octets consommés
 */
static int parse_telnet_command(const u_char *packet, int length, int verbosity, int indent) {
    if (length < 1) return 0;
    
    unsigned char iac = packet[0];
    if (iac != TELNET_IAC) return 0;
    
    if (length < 2) {
        // IAC incomplet
        if (verbosity >= 2) {
            for (int i = 0; i < indent; i++) printf(" ");
            printf("Telnet: IAC (incomplete)\n");
        }
        return 1;
    }
    
    unsigned char cmd = packet[1];
    
    // Vérifier si c'est une commande valide
    if (!is_telnet_command_byte(cmd)) {
        // IAC suivi d'un octet non-commande = IAC littéral (échappement)
        if (verbosity == 2) {
            for (int i = 0; i < indent; i++) printf(" ");
            printf("Telnet: IAC literal (0x%02X)\n", cmd);
        } else if (verbosity == 3) {
            for (int i = 0; i < indent; i++) printf(" ");
            printf("Telnet IAC Literal:\n");
            for (int i = 0; i < indent + 2; i++) printf(" ");
            printf("Value: 0x%02X ('%c')\n", cmd, isprint(cmd) ? cmd : '?');
        }
        return 2; // IAC + octet littéral
    }
    
    // Commande valide détectée
    char cmd_name[32];
    telnet_command_name(cmd, cmd_name, sizeof(cmd_name));
    
    if (verbosity == 2) {
        // Affichage concis
        for (int i = 0; i < indent; i++) printf(" ");
        if (telnet_command_needs_option(cmd) && length >= 3) {
            unsigned char opt = packet[2];
            printf("Telnet: %s %d\n", cmd_name, opt);
            return 3;
        } else if (cmd == 250) { // SB (Subnegotiation)
            // Chercher IAC SE
            int pos = 2;
            while (pos < length - 1) {
                if (packet[pos] == TELNET_IAC && packet[pos + 1] == 240) { // SE
                    printf("Telnet: %s (subnegotiation, %d bytes)\n", cmd_name, pos + 2);
                    return pos + 2;
                }
                pos++;
            }
            printf("Telnet: %s (subnegotiation, incomplete)\n", cmd_name);
            return length; // Consommer tout si SE non trouvé
        } else {
            printf("Telnet: %s\n", cmd_name);
            return 2;
        }
    } else if (verbosity == 3) {
        // Affichage détaillé
        for (int i = 0; i < indent; i++) printf(" ");
        printf("Telnet Command:\n");
        
        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("IAC: 0xFF\n");
        
        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Command: %s (0x%02X)\n", cmd_name, cmd);
        
        if (telnet_command_needs_option(cmd)) {
            if (length >= 3) {
                unsigned char opt = packet[2];
                for (int i = 0; i < indent + 2; i++) printf(" ");
                printf("Option: %d (0x%02X)\n", opt, opt);
                return 3;
            } else {
                for (int i = 0; i < indent + 2; i++) printf(" ");
                printf("Option: (missing)\n");
                return 2;
            }
        } else if (cmd == 250) { // SB
            // Subnegotiation: IAC SB ... IAC SE
            for (int i = 0; i < indent + 2; i++) printf(" ");
            printf("Subnegotiation Data:\n");
            int pos = 2;
            while (pos < length - 1) {
                if (packet[pos] == TELNET_IAC && packet[pos + 1] == 240) { // SE
                    for (int i = 0; i < indent + 4; i++) printf(" ");
                    printf("Length: %d bytes\n", pos - 2);
                    if (pos - 2 > 0 && pos - 2 <= 100) {
                        for (int i = 0; i < indent + 4; i++) printf(" ");
                        printf("Content: ");
                        for (int j = 2; j < pos; j++) {
                            unsigned char c = packet[j];
                            if (isprint(c)) putchar(c);
                            else printf("\\x%02X", c);
                        }
                        printf("\n");
                    }
                    return pos + 2;
                }
                pos++;
            }
            for (int i = 0; i < indent + 4; i++) printf(" ");
            printf("(incomplete, no SE found)\n");
            return length;
        }
        return 2;
    }
    
    return 0;
}

/**
 * Filtre les séquences ANSI (escape codes) d'une chaîne
 * Exemples: \x1b[01;32m, \x1b]0;title\x07, etc.
 */
static void filter_ansi_sequences(char *str) {
    char *src = str;
    char *dst = str;
    int in_escape = 0;
    int in_osc = 0; // OSC (Operating System Command): \x1b]...\x07
    
    while (*src) {
        if (in_osc) {
            // Dans une séquence OSC, chercher la fin (\x07 ou \x1b\)
            if (*src == '\x07' || (*src == '\x1b' && src[1] == '\\')) {
                in_osc = 0;
                if (*src == '\x1b') src++; // Consommer le backslash
            }
            src++;
            continue;
        }
        
        if (in_escape) {
            // Dans une séquence escape, chercher la fin (lettre ou '[' suivi de fin)
            if ((*src >= 'A' && *src <= 'Z') || (*src >= 'a' && *src <= 'z') || *src == '@') {
                in_escape = 0;
            } else if (*src == ']') {
                // OSC commence
                in_escape = 0;
                in_osc = 1;
            }
            src++;
            continue;
        }
        
        if (*src == '\x1b') {
            // Début d'une séquence escape
            in_escape = 1;
            src++;
            continue;
        }
        
        // Caractère normal, le copier
        *dst++ = *src++;
    }
    
    *dst = '\0';
}

/**
 * Vérifie si une chaîne contient seulement des caractères de contrôle ou est vide après nettoyage
 */
static int is_only_control_chars(const char *str) {
    if (!str || strlen(str) == 0) return 1;
    
    for (const char *p = str; *p; p++) {
        if (isprint((unsigned char)*p) && *p != ' ') {
            return 0; // Au moins un caractère imprimable non-espace
        }
    }
    return 1; // Seulement espaces ou caractères de contrôle
}

/**
 * Parse des données texte Telnet
 * Approche générique : utilise text_extract_line comme FTP/SMTP
 * Filtre les séquences ANSI pour un affichage propre
 */
static int parse_telnet_data(const u_char *packet, int length, int verbosity, int indent) {
    // Extraire une ligne si possible (approche générique)
    char line[512];
    int next = text_extract_line(packet, 0, length, line, sizeof(line));
    
    if (verbosity == 2) {
        for (int i = 0; i < indent; i++) printf(" ");
        if (next > 0) {
            // Filtrer les séquences ANSI
            filter_ansi_sequences(line);
            
            // Afficher la ligne (limiter la longueur)
            int display_len = strlen(line);
            if (display_len > 60) {
                char truncated[64];
                strncpy(truncated, line, 60);
                truncated[60] = '\0';
                printf("Telnet Data: %s...\n", truncated);
            } else {
                printf("Telnet Data: %s\n", line);
            }
            return next;
        } else {
            // Pas de ligne complète, afficher les premiers caractères (filtrés)
            char preview[64] = "";
            int preview_len = (length > 60) ? 60 : length;
            int preview_count = 0;
            for (int i = 0; i < preview_len && preview_count < 60; i++) {
                unsigned char c = packet[i];
                if (isprint(c) || c == '\t' || c == '\n' || c == '\r') {
                    if (c == '\r' || c == '\n') break;
                    preview[preview_count++] = c;
                } else if (c == TELNET_IAC) {
                    break;
                }
            }
            preview[preview_count] = '\0';
            filter_ansi_sequences(preview);
            
            if (preview_count > 0) {
                printf("Telnet Data: %s", preview);
                if (length > preview_len) printf("...");
                printf("\n");
            } else {
                printf("Telnet Data: %d bytes\n", length);
            }
            return length;
        }
    } else if (verbosity == 3) {
        for (int i = 0; i < indent; i++) printf(" ");
        printf("Telnet Data:\n");
        
        if (next > 0) {
            // Filtrer les séquences ANSI
            filter_ansi_sequences(line);
            
            for (int i = 0; i < indent + 2; i++) printf(" ");
            printf("Content: %s\n", line);
            for (int i = 0; i < indent + 2; i++) printf(" ");
            printf("Length: %d bytes\n", next);
            return next;
        } else {
            // Afficher les données brutes (limitées, avec filtrage ANSI)
            int display_len = (length > 200) ? 200 : length;
            char raw_preview[256] = "";
            int raw_count = 0;
            for (int i = 0; i < display_len && raw_count < 200; i++) {
                unsigned char c = packet[i];
                if (isprint(c) || c == '\t') {
                    raw_preview[raw_count++] = c;
                } else if (c == '\n') {
                    raw_preview[raw_count++] = '\\';
                    raw_preview[raw_count++] = 'n';
                } else if (c == '\r') {
                    raw_preview[raw_count++] = '\\';
                    raw_preview[raw_count++] = 'r';
                } else if (c == TELNET_IAC) {
                    break;
                } else {
                    // Caractère de contrôle, afficher en hex
                    char hex[5];
                    snprintf(hex, sizeof(hex), "\\x%02X", c);
                    for (int j = 0; hex[j] && raw_count < 200; j++) {
                        raw_preview[raw_count++] = hex[j];
                    }
                }
            }
            raw_preview[raw_count] = '\0';
            filter_ansi_sequences(raw_preview);
            
            for (int i = 0; i < indent + 2; i++) printf(" ");
            printf("Raw Data (%d bytes):\n", length);
            for (int i = 0; i < indent + 4; i++) printf(" ");
            printf("%s", raw_preview);
            if (length > display_len) printf("... (truncated)");
            printf("\n");
            return length;
        }
    }
    
    return 0;
}

/**
 * Fonction principale de parsing Telnet
 * Approche générique : détecte IAC et données texte sans liste exhaustive
 */
int parse_telnet(const u_char *packet, int length, int verbosity, int indent) {
    if (length < 1) return 0;
    
    int offset = 0;
    
    // Telnet peut contenir un mélange de commandes IAC et de données texte
    while (offset < length) {
        // Vérifier si on a une commande IAC
        if (packet[offset] == TELNET_IAC) {
            int consumed = parse_telnet_command(packet + offset, length - offset, verbosity, indent);
            if (consumed > 0) {
                offset += consumed;
            } else {
                // Erreur de parsing, consommer 1 octet pour éviter boucle infinie
                offset++;
            }
        } else {
            // Données texte (approche générique comme FTP/SMTP)
            int consumed = parse_telnet_data(packet + offset, length - offset, verbosity, indent);
            if (consumed > 0) {
                offset += consumed;
            } else {
                // Pas de ligne complète, consommer tout
                if (verbosity == 2) {
                    for (int i = 0; i < indent; i++) printf(" ");
                    printf("Telnet Data: %d bytes\n", length - offset);
                } else if (verbosity == 3) {
                    for (int i = 0; i < indent; i++) printf(" ");
                    printf("Telnet Data: %d bytes (binary or incomplete)\n", length - offset);
                }
                offset = length;
            }
        }
    }
    
    return offset;
}

/**
 * Résumé verbosité 1 pour Telnet
 * Approche similaire à FTP/SMTP : n'affiche que les lignes complètes significatives
 * Ignore les caractères individuels et les séquences de contrôle
 */
int telnet_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume, uint16_t src_port, uint16_t dst_port) {
    if ((int)caplen < offset_tcp_payload) return 0;
    
    int payload_len = caplen - offset_tcp_payload;
    if (payload_len < 1) return 0;
    
    const u_char *payload = packet + offset_tcp_payload;
    
    // Déterminer si c'est client (vers port 23) ou serveur (depuis port 23)
    int is_client = (dst_port == TELNET_PORT);
    (void)src_port; // Utilisé implicitement via !is_client
    
    // Ignorer les commandes IAC en verbosité 1 (trop verbeux, comme les options TCP)
    if (payload[0] == TELNET_IAC) {
        return 0; // Ne rien afficher pour les commandes IAC en v1
    }
    
    // Extraire une ligne complète (comme FTP/SMTP)
    char line[256];
    int next = text_extract_line(payload, 0, payload_len, line, sizeof(line));
    
    if (next > 0) {
        // Ligne complète trouvée
        // Nettoyer la ligne (enlever \r\n)
        int line_len = strlen(line);
        while (line_len > 0 && (line[line_len-1] == '\r' || line[line_len-1] == '\n')) {
            line[line_len-1] = '\0';
            line_len--;
        }
        
        // Filtrer les séquences ANSI
        filter_ansi_sequences(line);
        
        // Ignorer si la ligne ne contient que des caractères de contrôle
        if (is_only_control_chars(line)) {
            return 0;
        }
        
        // Limiter la longueur pour le résumé (comme FTP/SMTP)
        int display_len = strlen(line);
        if (display_len > 30) {
            line[30] = '\0';
            display_len = 30;
        }
        
        int remaining = 255 - strlen(resume);
        if (remaining > 50) {
            if (is_client) {
                snprintf(resume + strlen(resume), remaining, " | Telnet CMD: %.30s%s", line, (display_len == 30) ? "..." : "");
            } else {
                snprintf(resume + strlen(resume), remaining, " | Telnet SRV: %.30s%s", line, (display_len == 30) ? "..." : "");
            }
        }
        return 1;
    }
    
    // Pas de ligne complète : ignorer en verbosité 1 (comme FTP/SMTP qui retournent 0)
    // Cela évite d'afficher chaque caractère individuel
    return 0;
}