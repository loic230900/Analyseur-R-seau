/**
 * Post Office Protocol version 3 - récupération de courrier électronique.
 * Port standard : 110 (POP3), 995 (POP3S)
 */

#include "pop3.h"
#include "../util/textutils.h"
#include "../util/safe_string.h"
#include "../util/display_constants.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Liste des commandes POP3 valides */
static const char *pop3_commands[] = {
    "USER", "PASS", "APOP", "STAT", "LIST", "RETR", "DELE",
    "NOOP", "RSET", "QUIT", "TOP", "UIDL", "CAPA", NULL
};

/**
 * Masque le mot de passe dans une commande PASS
 * Format attendu: PASS password
 */
static void mask_password(char *line) {
    if(strncasecmp(line, "PASS ", 5) == 0)
        snprintf(line + 5, 250, "****");
}

/**
 * Extrait le message après +OK ou -ERR
 * @param line Ligne à analyser
 * @param skip Nombre de caractères à sauter (+OK = 3, -ERR =
 * @return Pointeur vers le message (dans line), ou chaîne vide
 */
static const char* extract_message(const char *line, int skip) {
    if((int)strlen(line) <= skip) return "";
    const char *msg = line + skip;
    while(*msg == ' ') msg++;
    return msg;
}

/**
 * Vérifie si la ligne est une commande POP3
 * @param line Ligne à analyser
 * @param len Longueur de la ligne
 * @return 1 si c'est une commande, 0 sinon
 */
static int is_command(const char *line, int len) {
    if(len < 3) return 0;
    for(int i = 0; pop3_commands[i]; i++) {
        int clen = (int)strlen(pop3_commands[i]);
        if(len >= clen && strncasecmp(line, pop3_commands[i], (size_t)clen) == 0)
            if(len == clen || line[clen] == ' ' || line[clen] == '\r')
                return 1;
    }
    return 0;
}

/**
 * Vérifie si la ligne est une réponse POP3
 * @param line Ligne à analyser
 * @param len Longueur de la ligne
 * @return 1 pour +OK, -1 pour -ERR, 0 sinon
 */
static int is_response(const char *line, int len) {
    if(len >= 3 && strncmp(line, "+OK", 3) == 0) return 1;
    if(len >= 4 && strncmp(line, "-ERR", 4) == 0) return -1;
    return 0;
}

/**
 *  Parse une commande POP3
 * @param packet Pointeur vers le payload POP3
 * @param length Longueur du payload
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent Indentation pour l'affichage
 * @return Nombre d'octets consommés
 */
static int parse_command(const u_char *packet, int length, int verbosity, int indent) {
    char line[256];
    int next = text_extract_line(packet, 0, length, line, sizeof(line));
    if(next < 0) return 0;
    
    mask_password(line);
    
    if(verbosity == 2) {
        print_indent(indent);
        printf("POP3 Commande: %s\n", line);
    } else if(verbosity == 3) {
        /* Séparer commande et arguments */
        char *space = strchr(line, ' ');
        print_indent(indent);
        printf("[L7] POP3 Commande:\n");
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
    return next;
}

/**
 *  Parse une réponse POP3 (gère les réponses multi-lignes)
 * @param packet Pointeur vers le payload POP3
 * @param length Longueur du payload
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent Indentation pour l'affichage
 * @return Nombre d'octets consommés
 */
static int parse_response(const u_char *packet, int length, int verbosity, int indent) {
    char line[256];
    int next = text_extract_line(packet, 0, length, line, sizeof(line));
    if(next < 0) return 0;
    
    int type = is_response(line, (int)strlen(line));
    const char *status = (type == 1) ? "+OK" : "-ERR";
    const char *msg = extract_message(line, (type == 1) ? 3 : 4);
    
    print_indent(indent);
    if(verbosity == 2) {
        printf("POP3 Réponse: %s%s%s\n", status, *msg ? " " : "", msg);
    } else {
        printf("[L7] POP3 Réponse:\n");
        print_indent(indent + 2);
        printf("Statut: %s\n", status);
        if(*msg) {
            print_indent(indent + 2);
            printf("Message: %s\n", msg);
        }
    }
    
    int offset = next;
    
    /* Réponses multi-lignes (+OK) : lire jusqu'à "." seul */
    if(type == 1) {
        while(offset < length && offset < 10000) {
            next = text_extract_line(packet, offset, length, line, sizeof(line));
            if(next < 0) break;
            if(strcmp(line, ".") == 0) return next;
            if(verbosity == 3) {
                print_indent(indent + 2);
                printf("  %s\n", line);
            }
            offset = next;
        }
    }
    return offset;
}


// Parse principal POP3 pour verbosités 2 et 3

int parse_pop3(const u_char *packet, int length, int verbosity, int indent) {
    if(length < 3) return 0;
    
    char header[256];
    int preview = (length < 255) ? length : 255;
    memcpy(header, packet, (size_t)preview);
    header[preview] = '\0';
    
    if(is_command(header, preview))
        return parse_command(packet, length, verbosity, indent);
    
    if(is_response(header, preview))
        return parse_response(packet, length, verbosity, indent);
    
    /* Données de mail (après RETR) */
    if(verbosity >= 2 && text_is_printable(packet, length > 200 ? 200 : length)) {
        print_indent(indent);
        printf("POP3 Données mail: %d octets\n", length);
        return length;
    }
    
    return 0;
}

// Résumé POP3 pour affichage concis

int pop3_v1_summary(const u_char *packet, int caplen, int offset, char *resume) {
    if(caplen < offset + 3) return 0;
    
    const u_char *pop3 = packet + offset;
    int len = caplen - offset;
    
    char line[128];
    int end = text_find_line_end(pop3, 0, len);
    if(end < 0 || end > 127) return 0;
    
    memcpy(line, pop3, (size_t)end);
    line[end] = '\0';
    mask_password(line);
    
    char info[128];
    
    /* Commande POP3 */
    if(is_command(line, end)) {
        snprintf(info, sizeof(info), " | POP3 %s", line);
        safe_strcat(resume, info, RESUME_BUFFER_SIZE);
        return 1;
    }
    
    /* Réponse POP3 */
    int type = is_response(line, end);
    if(type) {
        const char *msg = extract_message(line, (type == 1) ? 3 : 4);
        if(*msg)
            snprintf(info, sizeof(info), " | POP3 %s %s", (type == 1) ? "+OK" : "-ERR", msg);
        else
            snprintf(info, sizeof(info), " | POP3 %s", (type == 1) ? "+OK" : "-ERR");
        safe_strcat(resume, info, RESUME_BUFFER_SIZE);
        return 1;
    }
    
    return 0;
}
