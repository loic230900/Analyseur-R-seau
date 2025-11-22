#include "smtp.h"
#include "../util/textutils.h"
#include "../hexdump.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* Helpers de parsing de lignes déplacés dans textutils.c */

/**
 * Vérifie si une ligne est une commande SMTP
 * @param line: pointeur vers la ligne
 * @param len: longueur de la ligne
 * @return 1 si c'est une commande SMTP, 0 sinon
 */
static int is_smtp_command(const char *line, int len) {
    if (len < 4) return 0;
    
    const char *commands[] = {
        "HELO", "EHLO", "MAIL", "RCPT", "DATA", 
        "QUIT", "RSET", "VRFY", "NOOP", "AUTH", "STARTTLS"
    };
    int num_commands = sizeof(commands) / sizeof(commands[0]);
    
    for (int i = 0; i < num_commands; i++) {
        int cmd_len = strlen(commands[i]);
        if (len >= cmd_len && strncasecmp(line, commands[i], cmd_len) == 0) {
            // Vérifier qu'après la commande il y a un espace ou fin de ligne
            if (len == cmd_len || line[cmd_len] == ' ' || line[cmd_len] == ':')
                return 1;
        }
    }
    return 0;
}

/**
 * Vérifie si une ligne est une réponse SMTP (commence par 3 chiffres)
 * @param line: pointeur vers la ligne
 * @param len: longueur de la ligne
 * @return le code de réponse si valide, -1 sinon
 */
static int is_smtp_response(const char *line, int len) {
    if (len < 3) return -1;
    
    // Vérifier que les 3 premiers caractères sont des chiffres
    if (isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2])) {
        int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
        // Les codes SMTP sont entre 200 et 599
        if (code >= 200 && code <= 599)
            return code;
    }
    return -1;
}

/**
 * Parse et affiche une commande SMTP
 * @param packet: pointeur vers le début de l'en-tête SMTP
 * @param length: longueur totale des données SMTP
 * @param verbosity: niveau de verbosité (2 ou 3)
 * @param indent: indentation pour l'affichage
 * @return nombre total d'octets traités
 */
static int parse_smtp_command(const u_char *packet, int length, int verbosity, int indent) {
    char line[512];
    int offset = 0;

    // Extraction de la ligne de commande
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if (next < 0)
        return 0;

    // Verbosité 2 : affichage concis
    if (verbosity == 2) {
        for (int i = 0; i < indent; i++) printf(" ");
        printf("SMTP Command: %s\n", line);
    }
    // Verbosité 3 : affichage détaillé
    else if (verbosity == 3) {
        for (int i = 0; i < indent; i++) printf(" ");
        printf("SMTP Command:\n");
        
        // Extraire la commande et les arguments
        char cmd[16] = "";
        char args[256] = "";
        char *space = strchr(line, ' ');
        if (space) {
            int cmd_len = space - line;
            if (cmd_len < 16) {
                strncpy(cmd, line, cmd_len);
                cmd[cmd_len] = '\0';
            }
            // Arguments après l'espace
            char *arg_start = space + 1;
            while (*arg_start == ' ') arg_start++;
            strncpy(args, arg_start, sizeof(args) - 1);
        } else {
            strncpy(cmd, line, sizeof(cmd) - 1);
        }
        
        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Command: %s\n", cmd);
        
        if (strlen(args) > 0) {
            for (int i = 0; i < indent + 2; i++) printf(" ");
            printf("Arguments: %s\n", args);
        }
    }
    
    offset = next;
    
    // Si c'est DATA, tout ce qui suit est le contenu du mail jusqu'à ".\r\n"
    if (strncasecmp(line, "DATA", 4) == 0 && verbosity == 3) {
        // On ne parse pas le contenu ici, juste indiquer qu'il y a du data
        int remaining = length - offset;
        if (remaining > 0) {
            for (int i = 0; i < indent; i++) printf(" ");
            printf("Mail Content: %d bytes (not parsed)\n", remaining);
            offset = length; // Consommer tout
        }
    }
    
    return offset;
}

/**
 * Parse et affiche une réponse SMTP
 * @param packet: pointeur vers le début de l'en-tête SMTP
 * @param length: longueur totale des données SMTP
 * @param verbosity: niveau de verbosité (2 ou 3)
 * @param indent: indentation pour l'affichage
 * @return nombre total d'octets traités
 */
static int parse_smtp_response(const u_char *packet, int length, int verbosity, int indent) {
    char line[512];
    int offset = 0;

    // Extraction de la ligne de réponse
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if (next < 0)
        return 0;

    // Extraire le code et le message
    int code = 0;
    char message[256] = "";
    
    if (strlen(line) >= 3) {
        code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
        
        // Le message commence après le code et un espace/tiret
        if (strlen(line) > 4 && (line[3] == ' ' || line[3] == '-')) {
            strncpy(message, line + 4, sizeof(message) - 1);
        }
    }

    // Verbosité 2
    if (verbosity == 2) {
        for (int i = 0; i < indent; i++) printf(" ");
        printf("SMTP Response: %d %s\n", code, message);
    }
    // Verbosité 3
    else if (verbosity == 3) {
        for (int i = 0; i < indent; i++) printf(" ");
        printf("SMTP Response:\n");
        
        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Code: %d\n", code);
        
        for (int i = 0; i < indent + 2; i++) printf(" ");
        printf("Message: %s\n", message);
    }
    
    offset = next;
    
    // Les réponses multi-lignes (code suivi de '-')
    // Par exemple : "250-smtp.example.com\r\n250 SIZE 35882577\r\n"
    while (offset < length) {
        next = text_extract_line(packet, offset, length, line, sizeof(line));
        if (next < 0) break;
        
        // Si la ligne commence par le même code suivi de '-', c'est une continuation
        if (strlen(line) >= 3 && isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2])) {
            int line_code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
            if (line_code == code && strlen(line) > 3 && line[3] == '-') {
                // Ligne de continuation
                if (verbosity == 3) {
                    for (int i = 0; i < indent + 2; i++) printf(" ");
                    printf("  %s\n", line + 4);
                }
                offset = next;
                continue;
            } else if (line_code == code && strlen(line) > 3 && line[3] == ' ') {
                // Dernière ligne de la réponse multi-ligne
                if (verbosity == 3) {
                    for (int i = 0; i < indent + 2; i++) printf(" ");
                    printf("  %s\n", line + 4);
                }
                offset = next;
                break;
            }
        }
        // Sinon, fin de la réponse
        break;
    }
    
    return offset;
}

/**
 * Fonction principale de parsing SMTP
 */
int parse_smtp(const u_char *packet, int length, int verbosity, int indent) {
    if (length < 4) return 0; // Trop court pour SMTP
    
    // Convertir le début en string pour analyse
    char header_start[512];
    int preview_len = (length < 511) ? length : 511;
    memcpy(header_start, packet, preview_len);
    header_start[preview_len] = '\0';

    // Détection commande ou réponse
    if (is_smtp_command(header_start, preview_len)) {
        return parse_smtp_command(packet, length, verbosity, indent);
    } else if (is_smtp_response(header_start, preview_len) > 0) {
        return parse_smtp_response(packet, length, verbosity, indent);
    }
    
    // Cas particulier : contenu du mail (après DATA)
    // On peut détecter si c'est du texte ou si ça se termine par ".\r\n"
    if (verbosity == 3 && length > 0) {
        // Vérifier si c'est du texte imprimable
        int is_text = 1;
        for (int i = 0; i < length && i < 200; i++) {
            unsigned char c = packet[i];
            if (!isprint(c) && c != '\r' && c != '\n' && c != '\t') {
                is_text = 0;
                break;
            }
        }
        
        if (is_text) {
            for (int i = 0; i < indent; i++) printf(" ");
            printf("SMTP Mail Data: %d bytes\n", length);
            
            for (int i = 0; i < indent; i++) printf(" ");
            printf("---\n");
            fwrite(packet, 1, length > 500 ? 500 : length, stdout);
            if (length > 500) printf("\n... (truncated)");
            printf("\n");
            for (int i = 0; i < indent; i++) printf(" ");
            printf("---\n");
            return length;
        }
    }
    
    // Sinon, affichage générique pour verbosité 2
    if (verbosity == 2 && length > 0) {
        for (int i = 0; i < indent; i++) printf(" ");
        printf("SMTP Data: %d bytes\n", length);
        return length;
    }
    
    return 0;
}

/**
 * Résumé verbosité 1
 */
int smtp_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume) {
    if (caplen < offset_tcp_payload + 4)
        return 0;
    
    const u_char *smtp = packet + offset_tcp_payload;
    int smtp_len = caplen - offset_tcp_payload;

    char line[128];
    int end = text_find_line_end(smtp, 0, smtp_len);
    if (end < 0 || end > 127)
        return 0;

    memcpy(line, smtp, end);
    line[end] = '\0';

    // Commande SMTP
    if (is_smtp_command(line, end)) {
        char cmd[16] = "";
        char args[64] = "";
        sscanf(line, "%15s %63[^\r\n]", cmd, args);
        
        char info[128];
        if (strlen(args) > 0) {
            snprintf(info, sizeof(info), " | SMTP %s %s", cmd, args);
        } else {
            snprintf(info, sizeof(info), " | SMTP %s", cmd);
        }
        
        if (strlen(resume) + strlen(info) < 255) {
            strcat(resume, info);
        }
        return 1;
    }
    // Réponse SMTP
    else {
        int code = is_smtp_response(line, end);
        if (code > 0) {
            char msg[64] = "";
            if (end > 4 && (line[3] == ' ' || line[3] == '-')) {
                int msg_len = end - 4;
                if (msg_len > 63) msg_len = 63;
                memcpy(msg, line + 4, msg_len);
                msg[msg_len] = '\0';
            }
            
            char info[128];
            if (strlen(msg) > 0) {
                snprintf(info, sizeof(info), " | SMTP %d %s", code, msg);
            } else {
                snprintf(info, sizeof(info), " | SMTP %d", code);
            }
            
            if (strlen(resume) + strlen(info) < 255) {
                strcat(resume, info);
            }
            return 1;
        }
    }
    
    return 0;
}