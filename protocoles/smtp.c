/**
 * Analyseur du protocole SMTP (RFC 5321)
 * 
 * Ports standards : 25 (SMTP), 587 (submission), 465 (SMTPS)
 */

#include "smtp.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "util/textutils.h"
#include "util/safe_string.h"

/**
 * Vérifie si une ligne est une commande SMTP (4+ lettres majuscules)
 * @param line Ligne à analyser
 * @param len Longueur de la ligne
 * @return 1 si c'est une commande, 0 sinon
 */
static int is_command(const char *line, int len) {
    if(len < 4 || !isupper((unsigned char)line[0])) return 0;
    
    int i = 0;
    while(i < len && i < 20 && isupper((unsigned char)line[i])) i++;
    if(i < 4) return 0;
    
    /* Après la commande : espace, CRLF, ou ':' */
    if(i < len) {
        char c = line[i];
        if(c != ' ' && c != '\r' && c != '\n' && c != ':') return 0;
    }
    return 1;
}

/**
 * Vérifie si une ligne est une réponse SMTP (3 chiffres, 200-599)
 * @param line Ligne à analyser
 * @param len Longueur de la ligne
 * @return Code de réponse ou -1 si invalide
 */
static int get_response_code(const char *line, int len) {
    if(len < 3) return -1;
    if(!isdigit(line[0]) || !isdigit(line[1]) || !isdigit(line[2])) return -1;
    int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    return (code >= 200 && code <= 599) ? code : -1;
}

/**
 * Extrait le message après le code de réponse (après "NNN " ou "NNN-")
 * @param line Ligne à analyser
 * @param len Longueur de la ligne
 * @return Pointeur vers le message (dans line), ou chaîne vide
 */
static const char* extract_message(const char *line, int len) {
    if(len > 4 && (line[3] == ' ' || line[3] == '-')) return line + 4;
    return "";
}

/**
 *  Parse une commande SMTP
 * @param packet Pointeur vers le payload SMTP
 * @param length Longueur du payload
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent Indentation pour l'affichage
 * @return Nombre d'octets consommés
 */
static int parse_command(const u_char *packet, int length, int verbosity, int indent) {
    char line[256];
    int next = text_extract_line(packet, 0, length, line, sizeof(line));
    if(next < 0) return 0;
    
    print_indent(indent);
    if(verbosity == 2) {
        printf("SMTP Commande: %s\n", line);
    } else {
        /* Séparer commande et arguments */
        char *space = strchr(line, ' ');
        printf("[L7] SMTP Commande:\n");
        print_indent(indent + 2);
        if(space) {
            *space = '\0';
            printf("Commande: %s\n", line);
            print_indent(indent + 2);
            printf("Arguments: %s\n", space + 1);
        } else {
            printf("Commande: %s\n", line);
        }
    }
    
    /* DATA : le contenu du mail suit */
    if(strncasecmp(line, "DATA", 4) == 0 && verbosity == 3 && next < length) {
        print_indent(indent);
        printf("Contenu mail: %d octets\n", length - next);
    }
    
    return next;
}

/**
 * Parse une réponse SMTP (gère les réponses multi-lignes)
 * @param packet Pointeur vers le payload SMTP
 * @param length Longueur du payload
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent Indentation pour l'affichage
 *  
 * @return Nombre d'octets consommés
 */
static int parse_response(const u_char *packet, int length, int verbosity, int indent) {
    char line[256];
    int next = text_extract_line(packet, 0, length, line, sizeof(line));
    if(next < 0) return 0;
    
    int code = get_response_code(line, (int)strlen(line));
    const char *msg = extract_message(line, (int)strlen(line));
    
    print_indent(indent);
    if(verbosity == 2) {
        printf("SMTP Réponse: %d %s\n", code, msg);
    } else {
        printf("[L7] SMTP Réponse:\n");
        print_indent(indent + 2);
        printf("Code: %d\n", code);
        if(*msg) {
            print_indent(indent + 2);
            printf("Message: %s\n", msg);
        }
    }
    
    int offset = next;
    
    /* Réponses multi-lignes : "NNN-" = continuation, "NNN " = fin */
    while(offset < length) {
        next = text_extract_line(packet, offset, length, line, sizeof(line));
        if(next < 0) break;
        
        int len = (int)strlen(line);
        if(len >= 4 && get_response_code(line, len) == code) {
            if(verbosity == 3) {
                print_indent(indent + 2);
                printf("  %s\n", line + 4);
            }
            offset = next;
            if(line[3] == ' ') break;  /* Dernière ligne */
        } else {
            break;
        }
    }
    
    return offset;
}

//  Parse principal SMTP pour verbosités 2 et 3

int parse_smtp(const u_char *packet, int length, int verbosity, int indent) {
    if(length < 4) return 0;
    
    char header[256];
    int preview = (length < 255) ? length : 255;
    memcpy(header, packet, (size_t)preview);
    header[preview] = '\0';
    
    if(is_command(header, preview))
        return parse_command(packet, length, verbosity, indent);
    
    if(get_response_code(header, preview) > 0)
        return parse_response(packet, length, verbosity, indent);
    
    /* Données mail (après DATA) */
    if(verbosity >= 2 && text_is_printable(packet, length > 200 ? 200 : length)) {
        print_indent(indent);
        printf("SMTP Données mail: %d octets\n", length);
        if(verbosity == 3) {
            print_indent(indent);
            printf("---\n");
            fwrite(packet, 1, (size_t)(length > 500 ? 500 : length), stdout);
            if(length > 500) printf("\n... (tronqué)");
            printf("\n");
            print_indent(indent);
            printf("---\n");
        }
        return length;
    }
    
    return 0;
}

// Résumé SMTP pour affichage concis

int smtp_v1_summary(const u_char *packet, int caplen, int offset, char *resume) {
    if(caplen < offset + 4) return 0;
    
    const u_char *smtp = packet + offset;
    int len = caplen - offset;
    
    char line[128];
    int end = text_find_line_end(smtp, 0, len);
    if(end < 0 || end > 127) return 0;
    
    memcpy(line, smtp, (size_t)end);
    line[end] = '\0';
    
    char info[128];
    
    /* Commande SMTP */
    if(is_command(line, end)) {
        /* Tronquer la ligne pour éviter débordement */
        char cmd_short[100];
        strncpy(cmd_short, line, sizeof(cmd_short) - 1);
        cmd_short[sizeof(cmd_short) - 1] = '\0';
        snprintf(info, sizeof(info), " | SMTP %s", cmd_short);
        safe_strcat(resume, info, RESUME_BUFFER_SIZE);
        return 1;
    }
    
    /* Réponse SMTP */
    int code = get_response_code(line, end);
    if(code > 0) {
        const char *msg = extract_message(line, end);
        if(*msg) {
            char msg_short[100];
            strncpy(msg_short, msg, sizeof(msg_short) - 1);
            msg_short[sizeof(msg_short) - 1] = '\0';
            snprintf(info, sizeof(info), " | SMTP %d %s", code, msg_short);
        } else {
            snprintf(info, sizeof(info), " | SMTP %d", code);
        }
        safe_strcat(resume, info, RESUME_BUFFER_SIZE);
        return 1;
    }
    
    return 0;
}
