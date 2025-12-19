/**

Analyseur de messages Telnet (couche 7 - Application)
 * 
 * Ce module implémente le parsing des échanges Telnet conformément aux RFCs :
 * - RFC 854 : Telnet Protocol Specification
 * - RFC 855 : Telnet Option Specifications
 * - RFC 856-861 : Options Telnet standard
 * 
 * Telnet fournit une communication bidirectionnelle orientée texte via un
 * terminal virtuel. Protocole historique, remplacé par SSH pour la sécurité.
 * 
 * Port standard : 23
 * 
 * Structure Telnet :
 * - Données normales : texte ASCII
 * - Séquences de commande : IAC (255) suivi de commandes
 *   - IAC DO/DONT/WILL/WONT (251-254) : Négociation d'options
 *   - IAC SB ... IAC SE : Sous-négociation
 * 
 * Commandes principales :
 * - IAC (255) : Interpret As Command - escape pour commandes
 * - WILL (251) : Le sender va utiliser l'option
 * - WONT (252) : Le sender refuse l'option
 * - DO (253) : Le receiver doit utiliser l'option
 * - DONT (254) : Le receiver ne doit pas utiliser l'option
 * - SB (250) : Début sous-négociation
 * - SE (240) : Fin sous-négociation
 * 
 * Options analysées : ECHO, SGA, NAWS, TERMINAL-TYPE, etc.
 * 
 */

#include "telnet.h"
#include "../util/textutils.h"
#include "../hexdump.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/**
 * Vérifie si un octet est une commande Telnet valide (240-255)
 * RFC 854: Commands are in range 240-255
 */
static int is_telnet_command_byte(unsigned char byte) {
    return (byte >= 240);  // unsigned char is always <= 255
}

/**
 * Obtient le nom d'une commande Telnet de manière générique
 * Approche générique : construit le nom à partir de la valeur
 */
static void telnet_command_name(unsigned char cmd, char *buf, int buf_len) {
    // Commandes courantes avec noms spécifiques
    switch(cmd) {
        case 255: snprintf(buf, (size_t)buf_len, "IAC"); return;
        case 254: snprintf(buf, (size_t)buf_len, "DONT"); return;
        case 253: snprintf(buf, (size_t)buf_len, "DO"); return;
        case 252: snprintf(buf, (size_t)buf_len, "WONT"); return;
        case 251: snprintf(buf, (size_t)buf_len, "WILL"); return;
        case 250: snprintf(buf, (size_t)buf_len, "SB"); return;
        case 240: snprintf(buf, (size_t)buf_len, "SE"); return;
        default:
            // Pour les autres, afficher la valeur hex
            snprintf(buf, (size_t)buf_len, "CMD_0x%02X", cmd);
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
 * Handles IAC doubling (IAC IAC = literal 0xFF)
 * @return nombre d'octets consommés
 */
static int parse_telnet_command(const u_char *packet, int length, int verbosity, int indent) {
    if (length < 1) return 0;
    
    unsigned char iac = packet[0];
    if (iac != TELNET_IAC) return 0;
    
    if (length < 2) {
        // IAC incomplet
        if (verbosity >= 2) {
            print_indent(indent);
            printf("Telnet: IAC (incomplete)\n");
        }
        return 1;
    }
    
    unsigned char cmd = packet[1];
    
    // Gérer IAC IAC (0xFF échappé - octet littéral)
    if (cmd == TELNET_IAC) {
        if (verbosity >= 3) {
            print_indent(indent);
            printf("Telnet: IAC IAC (literal 0xFF)\n");
        }
        return 2;
    }
    
    // Vérifier si c'est un octet de commande valide
    if (!is_telnet_command_byte(cmd)) {
        // IAC suivi d'un octet non-commande = IAC littéral (échappement)
        if (verbosity == 2) {
            print_indent(indent);
            printf("Telnet: IAC literal (0x%02X)\n", cmd);
        } else if (verbosity == 3) {
            print_indent(indent);
            printf("Telnet IAC Literal:\n");
            print_indent(indent + 2);
            printf("Value: 0x%02X ('%c')\n", cmd, isprint(cmd) ? cmd : '?');
        }
        return 2; // IAC + octet littéral
    }
    
    // Commande valide détectée
    char cmd_name[32];
    telnet_command_name(cmd, cmd_name, sizeof(cmd_name));
    
    if (verbosity == 2) {
        // Affichage concis
        print_indent(indent);
        if (telnet_command_needs_option(cmd) && length >= 3) {
            unsigned char opt = packet[2];
            printf("Telnet: %s %d\n", cmd_name, opt);
            return 3;
        } else if (cmd == 250) { // SB (Sousnégociation)
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
        print_indent(indent);
        printf("[L7] Telnet Command:\n");
        
        print_indent(indent + 2);
        printf("IAC: 0xFF\n");
        
        print_indent(indent + 2);
        printf("Command: %s (0x%02X)\n", cmd_name, cmd);
        
        if (telnet_command_needs_option(cmd)) {
            if (length >= 3) {
                unsigned char opt = packet[2];
                print_indent(indent + 2);
                printf("Option: %d (0x%02X)\n", opt, opt);
                return 3;
            } else {
                print_indent(indent + 2);
                printf("Option: (missing)\n");
                return 2;
            }
        } else if (cmd == 250) { // SB
            // Subnegotiation: IAC SB ... IAC SE
            print_indent(indent + 2);
            printf("Subnegotiation Data:\n");
            int pos = 2;
            while (pos < length - 1) {
                if (packet[pos] == TELNET_IAC && packet[pos + 1] == 240) { // SE
                    print_indent(indent + 4);
                    printf("Length: %d bytes\n", pos - 2);
                    if (pos - 2 > 0 && pos - 2 <= 100) {
                        print_indent(indent + 4);
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
            print_indent(indent + 4);
            printf("(incomplete, no SE found)\n");
            return length;
        }
        return 2;
    }
    
    return 0;
}

/**
 * Filtre les séquences ANSI/escape codes de manière robuste
 * Handles: CSI sequences, OSC sequences, simple escapes
 * Applied only once to avoid over-processing
 */
static void filter_ansi_sequences(char *str) {
    if (!str) return;
    
    char *src = str;
    char *dst = str;
    
    while (*src) {
        if (*src == '\x1b' && src[1]) { // ESC with next char
            if (src[1] == '[') {
                // CSI sequence: \x1b[...m ou \x1b[...lettre
                src += 2; // Skip ESC[
                while (*src && !(*src >= 'A' && *src <= 'Z') && 
                       !(*src >= 'a' && *src <= 'z') && 
                       *src != '@' && *src != '~' && *src != 'm') {
                    src++;
                }
                if (*src) src++; // Skip le caractère de fin
            } else if (src[1] == ']') {
                // OSC sequence: ESC] ... BEL ou ESC] ... ESC backslash
                src += 2; // Skip ESC]
                while (*src && *src != '\x07') {
                    if (*src == '\x1b' && src[1] == '\\') {
                        src += 2;
                        break;
                    }
                    src++;
                }
                if (*src == '\x07') src++;
            } else if (src[1] == '(' || src[1] == ')') {
                // Charset selection: \x1b(B ou \x1b)0
                src += 2;
                if (*src) src++;
            } else {
                // Autres séquences simples: \x1bX
                src += 2;
            }
        } else {
            // Keep normal characters
            *dst++ = *src++;
        }
    }
    
    *dst = '\0';
}

/**
 * Vérifie si une chaîne est vide ou contient seulement des espaces/tabs
 * Simplifié: n'élimine plus le contenu légitime
 */
static int is_empty_or_whitespace(const char *str) {
    if (!str || strlen(str) == 0) return 1;
    
    for (const char *p = str; *p; p++) {
        if (*p != ' ' && *p != '\t') {
            return 0; // Found non-whitespace
        }
    }
    return 1; // Only whitespace
}

/**
 * Parse des données texte Telnet
 * Simplifié: montre toutes les données, supporte single-char input
 * @param is_server_to_client 1 if server->client (IN), 0 if client->server (OUT)
 */
static int parse_telnet_data(const u_char *packet, int length, int verbosity, int indent, int is_server_to_client) {
    if (length < 1) return 0;
    
    // Trouver la fin des données (soit IAC, soit fin du paquet)
    int data_end = 0;
    while (data_end < length && packet[data_end] != TELNET_IAC) {
        data_end++;
    }
    
    if (data_end == 0) return 0; // Pas de données
    
    // Maintenant on a data_end octets de données pures
    if (verbosity == 2) {
        print_indent(indent);
        
        // Essayer d'extraire une ligne complète
        char line[512];
        int next = text_extract_line(packet, 0, data_end, line, sizeof(line));
        
        if (next > 0 && strlen(line) > 0) {
            // Ligne complète trouvée
            filter_ansi_sequences(line);
            
            if (!is_empty_or_whitespace(line)) {
                int display_len = (int)strlen(line);
                const char *dir = is_server_to_client ? "IN" : "OUT";
                if (display_len > 70) {
                    char truncated[74];
                    strncpy(truncated, line, 70);
                    truncated[70] = '\0';
                    printf("Telnet %s: %s...\n", dir, truncated);
                } else {
                    printf("Telnet %s: %s\n", dir, line);
                }
            }
        } else {
            // Pas de ligne complète - peut être un seul caractère (normal en Telnet)
            char preview[256] = "";
            int preview_count = 0;
            
            for (int i = 0; i < data_end && preview_count < 200; i++) {
                unsigned char c = packet[i];
                if (isprint(c)) {
                    preview[preview_count++] = (char)c;
                } else if (c == '\t') {
                    preview[preview_count++] = '\t';
                } else if (c == '\n' || c == '\r') {
                    // Ignore in preview; will render controls explicitly below
                    continue;
                }
            }
            preview[preview_count] = '\0';
            filter_ansi_sequences(preview);
            
            // Afficher même un seul caractère (important pour Telnet interactif)
            const char *dir = is_server_to_client ? "IN" : "OUT";
            if (!is_empty_or_whitespace(preview)) {
                int display_len = (int)strlen(preview);
                if (display_len > 70) {
                    preview[70] = '\0';
                    printf("Telnet %s: %s...\n", dir, preview);
                } else if (display_len > 0) {
                    printf("Telnet %s: %s\n", dir, preview);
                }
            } else if (data_end > 0) {
                // Représentation explicite des caractères de contrôle (\r, \n, \t, etc.)
                char ctrlrepr[128];
                int rp = 0;
                for (int i = 0; i < data_end && rp < (int)sizeof(ctrlrepr) - 4; i++) {
                    unsigned char c = packet[i];
                    if (c == '\r') { ctrlrepr[rp++] = '\\'; ctrlrepr[rp++] = 'r'; }
                    else if (c == '\n') { ctrlrepr[rp++] = '\\'; ctrlrepr[rp++] = 'n'; }
                    else if (c == '\t') { ctrlrepr[rp++] = '\\'; ctrlrepr[rp++] = 't'; }
                    else if (isprint(c)) { ctrlrepr[rp++] = (char)c; }
                    else {
                        // \xHH notation for other controls
                        char hex[5];
                        snprintf(hex, sizeof(hex), "\\x%02X", c);
                        for (int j = 0; hex[j] && rp < (int)sizeof(ctrlrepr) - 1; j++) {
                            ctrlrepr[rp++] = hex[j];
                        }
                    }
                }
                ctrlrepr[rp] = '\0';
                if (rp > 0) {
                    printf("Telnet %s: %s\n", dir, ctrlrepr);
                } else {
                    printf("Telnet %s: (%d bytes)\n", dir, data_end);
                }
            }
        }
        
        return data_end;
        
    } else if (verbosity == 3) {
        print_indent(indent);
        printf("Telnet Data:\n");
        
        // Essayer une ligne complète d'abord
        char line[512];
        int next = text_extract_line(packet, 0, data_end, line, sizeof(line));
        
        if (next > 0 && strlen(line) > 0) {
            filter_ansi_sequences(line);
            
            print_indent(indent + 2);
            printf("Line: %s\n", line);
            print_indent(indent + 2);
            printf("Length: %d bytes\n", next);
        } else {
            // Afficher les données brutes avec nettoyage
            char raw_text[512] = "";
            int raw_count = 0;
            
            for (int i = 0; i < data_end && raw_count < 400; i++) {
                unsigned char c = packet[i];
                if (isprint(c)) {
                    raw_text[raw_count++] = (char)c;
                } else if (c == '\t') {
                    raw_text[raw_count++] = '\t';
                } else if (c == '\n') {
                    if (raw_count < 398) {
                        raw_text[raw_count++] = '\\';
                        raw_text[raw_count++] = 'n';
                    }
                } else if (c == '\r') {
                    if (raw_count < 398) {
                        raw_text[raw_count++] = '\\';
                        raw_text[raw_count++] = 'r';
                    }
                } else {
                    // Autres caractères de contrôle en notation hex
                    char hex[6];
                    snprintf(hex, sizeof(hex), "\\x%02X", c);
                    for (int j = 0; hex[j] && raw_count < 400; j++) {
                        raw_text[raw_count++] = hex[j];
                    }
                }
            }
            raw_text[raw_count] = '\0';
            filter_ansi_sequences(raw_text);
            
            print_indent(indent + 2);
            printf("Content (%d bytes): %s\n", data_end, raw_text);
        }
        
        return data_end;
    }
    
    return data_end;
}

/**
 * Fonction principale de parsing Telnet
 * Approche générique : détecte IAC et données texte sans liste exhaustive
 */
int parse_telnet(const u_char *packet, int length, int verbosity, int indent, uint16_t src_port, uint16_t dst_port) {
    if (length < 1) return 0;
    
    int offset = 0;
    
    // Déterminer la direction : si dst_port == 23, c'est client->server (OUT)
    //                           si src_port == 23, c'est server->client (IN)
    int is_server_to_client = (src_port == TELNET_PORT) ? 1 : 0;
    (void)dst_port; // Suppress unused warning - direction determined by src_port
    
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
            int consumed = parse_telnet_data(packet + offset, length - offset, verbosity, indent, is_server_to_client);
            if (consumed > 0) {
                offset += consumed;
            } else {
                // Pas de ligne complète, consommer tout
                const char *dir = is_server_to_client ? "IN" : "OUT";
                if (verbosity == 2) {
                    print_indent(indent);
                    printf("Telnet %s: %d bytes\n", dir, length - offset);
                } else if (verbosity == 3) {
                    print_indent(indent);
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
 * Montre tout le contenu sans filtrage excessif
 * Supporte character-by-character et multi-line output
 */
int telnet_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume, uint16_t src_port, uint16_t dst_port) {
    if ((int)caplen < offset_tcp_payload) return 0;
    
    int payload_len = caplen - offset_tcp_payload;
    if (payload_len < 1) return 0;
    
    const u_char *payload = packet + offset_tcp_payload;
    
    // Déterminer la direction
    int is_client = (dst_port == TELNET_PORT);
    (void)src_port; // Éviter warning unused
    
    // Si commence par IAC, c'est une commande ou negotiation
    if (payload[0] == TELNET_IAC) {
        int remaining = 255 - (int)strlen(resume);
        if (remaining > 20) {
            if (is_client) {
                snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet OUT: cmd");
            } else {
                snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet IN: cmd");
            }
        }
        return 1;
    }
    
    // Extraire du contenu pour affichage
    char display[128] = "";
    int display_count = 0;
    
    // Essayer d'extraire une ligne complète d'abord
    char line[256];
    int next = text_extract_line(payload, 0, payload_len, line, sizeof(line));
    
    if (next > 0 && strlen(line) > 0) {
        // Ligne complète trouvée - filtrer ANSI une seule fois
        filter_ansi_sequences(line);
        
        // Trim trailing whitespace
        int line_len = (int)strlen(line);
        while (line_len > 0 && (line[line_len-1] == ' ' || line[line_len-1] == '\t')) {
            line[line_len-1] = '\0';
            line_len--;
        }
        
        if (!is_empty_or_whitespace(line)) {
            strncpy(display, line, (size_t)(sizeof(display) - 1));
            display[sizeof(display) - 1] = '\0';
            display_count = (int)strlen(display);
        }
    } else {
        // Pas de ligne complète - extraire caractères imprimables (normal pour Telnet)
        // Single-character input is common in interactive sessions
        for (int i = 0; i < payload_len && display_count < 100; i++) {
            unsigned char c = payload[i];
            if (isprint(c)) {
                display[display_count++] = (char)c;
            } else if (c == '\t') {
                display[display_count++] = ' ';
            }
        }
        display[display_count] = '\0';
        filter_ansi_sequences(display);
        
        // Trim après filtrage
        display_count = (int)strlen(display);
        while (display_count > 0 && display[display_count-1] == ' ') {
            display[display_count-1] = '\0';
            display_count--;
        }
    }
    
    // Afficher le résultat
    int remaining = 255 - (int)strlen(resume);
    if (remaining > 20) {
        if (!is_empty_or_whitespace(display) && display_count > 0) {
            // On a du contenu à afficher
            int max_display = 35;
            if (display_count > max_display) {
                display[max_display] = '\0';
                if (is_client) {
                    snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet OUT: %s...", display);
                } else {
                    snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet IN: %s...", display);
                }
            } else {
                if (is_client) {
                    snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet OUT: %s", display);
                } else {
                    snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet IN: %s", display);
                }
            }
        } else {
            // Pas de contenu affichable ou seulement whitespace
            if (is_client) {
                snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet OUT: data");
            } else {
                snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet IN: data");
            }
        }
    }
    return 1;
}