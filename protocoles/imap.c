/**
 * Ce module implémente le parsing des échanges IMAP 
 */

#include "imap.h"
#include "../util/textutils.h"  /* Utilise le module commun */
#include "../hexdump.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "../util/safe_string.h"

/**
 * Masque le mot de passe dans une commande LOGIN
 * Format attendu: TAG LOGIN username password
 * Remplace password par ****
 * 
 * @param line: ligne à traiter 
 */
static void mask_login_password(char *line) {
    // Vérifier si c'est une commande LOGIN
    char tag[64] = "", cmd[32] = "", user[128] = "", pass[128] = "";
    
    // Essayer de parser 4 tokens : TAG COMMANDE USER PASS
    int matched = sscanf(line, "%63s %31s %127s %127s", tag, cmd, user, pass);
    
    // Si on a bien 4 tokens et que la commande est LOGIN
    if (matched == 4 && strcasecmp(cmd, IMAP_CMD_LOGIN) == 0) {
        // Reconstruire la ligne avec mot de passe masqué
        snprintf(line, 255, "%s %s %s ****", tag, cmd, user);
    }
}

/**
 * Détecte si la ligne est une commande taggée client: <TAG> <CMD> ...
 * @param line Ligne à analyser
 * @return 1 si c'est une commande taggée, 0 sinon
 */
static int imap_is_tagged_command(const char *line) {
    // TAG: alpha/num (souvent lettres + chiffres), puis espace + commande en majuscule
    const char *p = line;
    if(!isalnum((unsigned char)*p)) return 0;
    while(isalnum((unsigned char)*p)) p++;
    if(*p != ' ') return 0;
    p++; // Commande suivante
    return isalpha((unsigned char)*p);
}

/**
 * Extrait tag + commande + reste.
 * @param line Ligne à analyser
 * @param tag Buffer pour le tag
 * @param tag_sz Taille du buffer tag
 * @param cmd Buffer pour la commande
 * @param cmd_sz Taille du buffer commande
 * @param args Buffer pour le reste des arguments
 * @param args_sz Taille du buffer args
 * @return 1 si succès, 0 sinon
 */
static int imap_parse_tagged_command(char *line, char *tag, int tag_sz, char *cmd, int cmd_sz, char *args, int args_sz){
    char *p = line;
    int i=0;
    while(isalnum((unsigned char)*p) && i < tag_sz -1) tag[i++] = *p++;
    tag[i]='\0';
    if(*p!=' ') return 0;
    p++; i=0;
    while(isalpha((unsigned char)*p) && i < cmd_sz -1) cmd[i++] = *p++;
    cmd[i]='\0';
    while(*p==' ') p++;
    strncpy(args, p, (size_t)(args_sz-1)); args[args_sz-1]='\0';
    return 1;
}

/**
 * Détecte réponse taggée serveur: <TAG> (OK|NO|BAD|PREAUTH|BYE) ...
 * @param line Ligne à analyser
 * @return 1 si c'est une réponse taggée, 0 sinon 
 */
static int imap_is_tagged_response(const char *line) {
    char tag[32], status[16];
    if(sscanf(line, "%31s %15s", tag, status) != 2) return 0; // Format invalide
    if(!isalnum((unsigned char)tag[0])) return 0; // Tag doit être alphanumérique
    return (!strcasecmp(status,"OK") || !strcasecmp(status,"NO") ||
            !strcasecmp(status,"BAD") || !strcasecmp(status,"PREAUTH") ||
            !strcasecmp(status,"BYE"));
}

/**
 * Détecte ligne untagged: commence par '* '
 * @param line Ligne à analyser
 * @return 1 si c'est une ligne untagged, 0 sinon   
 */
static int imap_is_untagged(const char *line){
    return (line[0]=='*' && line[1]==' ');
}

// Parsing principal IMAP pour verbosités 2 et 3

int parse_imap(const u_char *packet, int length, int verbosity, int indent){
    if(length < 4) return 0;
    int offset = 0;
    int consumed = 0;
    int line_count = 0;

    if(verbosity >= 2){
        print_indent(indent);
        printf("IMAP:\n");
    }

    // Parcourir les lignes jusqu'à épuisement du buffer
    while(offset < length){
        char line[512];
        int next = text_extract_line(packet, offset, length, line, sizeof(line));
        if(next < 0) break; // ligne non complète dans ce segment => arrêter
        offset = next;
        line_count++;
        mask_login_password(line); // Masquage mot de passe éventuel

        if(verbosity == 2){
            // Une seule ligne par entité (limiter volume)
            if(imap_is_tagged_command(line)){
                char tag[32], cmd[32], args[256];
                if(imap_parse_tagged_command(line, tag, sizeof(tag), cmd, sizeof(cmd), args, sizeof(args))){
                    print_indent(indent + 2);
                    printf("C %s %s %s\n", tag, cmd, args);
                    if(!strcasecmp(cmd, "STARTTLS")){ // Détection STARTTLS
                        print_indent(indent + 4);
                        printf("(Note: subsequent traffic will be TLS encrypted)\n");
                    }
                }
            } else if(imap_is_tagged_response(line)){
                print_indent(indent + 2);
                printf("S %s\n", line);
            } else if(imap_is_untagged(line)){
                print_indent(indent + 2);
                printf("* %s\n", line+2);
            } else { // Autres (peut être continuation literal ou IDLE data)
                print_indent(indent + 2);
                printf("? %s\n", line);
            }
        } else if(verbosity == 3){
            if(imap_is_tagged_command(line)){
                char tag[32], cmd[32], args[256];
                if(imap_parse_tagged_command(line, tag, sizeof(tag), cmd, sizeof(cmd), args, sizeof(args))){
                    print_indent(indent);
                    printf("[L7] IMAP Client Command:\n      Tag: %s\n      Command: %s\n", tag, cmd);
                    if(strlen(args)>0){
                        print_indent(indent);
                        printf("      Args: %s\n", args);
                    }
                    if(!strcasecmp(cmd, "STARTTLS")){ // Détection STARTTLS
                        print_indent(indent);
                        printf("      Note: After this command, subsequent traffic will be TLS encrypted.\n");
                    }
                }
            } else if(imap_is_tagged_response(line)){
                char tag[32], status[16], rest[400]="";
                sscanf(line, "%31s %15s %399[^\r\n]", tag, status, rest); // Extraire tag + status + message
                print_indent(indent);
                printf("[L7] IMAP Server Response:\n      Tag: %s\n      Status: %s\n", tag, status);
                if(strlen(rest)>0){
                    print_indent(indent);
                    printf("      Info: %s\n", rest);
                }
            } else if(imap_is_untagged(line)){ // Exemple: "* 23 EXISTS" / "* OK [CAPABILITY ...]"
                print_indent(indent);
                printf("[L7] IMAP Untagged:\n      %s\n", line+2);
            } else {
                print_indent(indent);
                printf("[L7] IMAP Other:\n      %s\n", line);
            }
        }

        consumed = offset;
        // Limiter pour ne pas déborder
        if((line_count > 50 && verbosity == 2) || (line_count > 120 && verbosity == 3)){
            print_indent(indent);
            printf("    (Truncated after %d lines)\n", verbosity == 2 ? 50 : 120);
            break;
        }
    }
    return consumed;
}

// Résumé IMAP pour affichage concis 

int imap_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume){
    if(caplen < offset_tcp_payload + 4) return 0;
    const u_char *imap = packet + offset_tcp_payload;
    int imap_len = caplen - offset_tcp_payload;

    char line[128], info[128];
    int end = text_find_line_end(imap, 0, imap_len);
    if(end < 0 || end > 120) return 0;
    memcpy(line, imap, (size_t)end);
    line[end] = '\0';
    mask_login_password(line);

    // Tag + commande
    if(imap_is_tagged_command(line)){
        char tag[32], cmd[32], args[64];
        if(imap_parse_tagged_command(line, tag, sizeof(tag), cmd, sizeof(cmd), args, sizeof(args))){
            snprintf(info, sizeof(info), " | IMAP %s %s", tag, cmd);
            safe_strcat(resume, info, RESUME_BUFFER_SIZE);
            return 1;
        }
    }
    // Réponse taggée
    if(imap_is_tagged_response(line)){
        char tag[32], status[16];
        if(sscanf(line, "%31s %15s", tag, status)==2){
            snprintf(info, sizeof(info), " | IMAP %s %s", tag, status);
            safe_strcat(resume, info, RESUME_BUFFER_SIZE);
            return 1;
        }
    }
    // Untagged - Exemple: * OK, * CAPABILITY
    if(imap_is_untagged(line)){
        char *p = line+2;
        while(*p==' ') p++;
        char first[32]="";
        sscanf(p, "%31s", first);
        snprintf(info, sizeof(info), " | IMAP * %s", first);
        safe_strcat(resume, info, RESUME_BUFFER_SIZE);
        return 1;
    }
    return 0;
}