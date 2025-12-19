/**

Analyseur de messages FTP (couche 7 - Application)
 * 
 * Ce module implémente le parsing des échanges FTP conformément à la RFC 959.
 * FTP (File Transfer Protocol) permet le transfert de fichiers entre systèmes.
 * 
 * Caractéristiques :
 * - Protocole textuel basé sur des lignes (CRLF)
 * - Deux connexions séparées : contrôle (port 21) et données (port 20)
 * - Mode actif : serveur se connecte au client
 * - Mode passif : client se connecte au serveur (PASV/EPSV)
 * 
 * Commandes FTP principales :
 * - USER/PASS : Authentification
 * - PWD/CWD : Navigation répertoires
 * - LIST/NLST : Listage de répertoire
 * - RETR/STOR : Téléchargement/Upload
 * - PASV/EPSV : Mode passif
 * - TYPE : Mode transfert (A=ASCII, I=Binaire)
 * - QUIT : Déconnexion
 * 
 * Codes de réponse : 1xx (info), 2xx (succès), 3xx (intermédiaire),
 *                    4xx (erreur temporaire), 5xx (erreur permanente)
 * 
 */

#include "ftp.h"
#include "../util/textutils.h"
#include "../hexdump.h"
#include "../util/safe_string.h"
#include "../util/display_constants.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/**
 * Vérifie si une ligne est une commande FTP
 * Approche générique : détecte toute commande FTP valide selon RFC 959
 * Format : 1-8 caractères alphabétiques en majuscules, suivis d'un espace ou CRLF
 * @param line: pointeur vers la ligne
 * @param len: longueur de la ligne
 * @return 1 si c'est une commande FTP, 0 sinon
 */
static int is_ftp_command(const char *line, int len){
    if (len < 1)
        return 0;

    // Vérifier que le premier caractère est alphabétique
    if (!isalpha((unsigned char)line[0]))
        return 0;

    // Compter les caractères alphabétiques consécutifs
    int cmd_len = 0;
    while (cmd_len < len && cmd_len < 8 && isalpha((unsigned char)line[cmd_len])) {
        cmd_len++;
    }

    // Une commande doit avoir au moins 1 caractère et au plus 8
    if (cmd_len == 0 || cmd_len > 8)
        return 0;

    // Après la commande, il doit y avoir :
    // - Fin de ligne (CRLF ou LF)
    // - Un espace (suivi d'arguments optionnels)
    // - Un caractère de contrôle (tab, etc.)
    if (cmd_len < len) {
        unsigned char next = (unsigned char)line[cmd_len];
        if (next != ' ' && next != '\r' && next != '\n' && next != '\t') {
            return 0;
        }
    }

    // Vérifier que tous les caractères de la commande sont en majuscules
    for (int i = 0; i < cmd_len; i++) {
        if (!isupper((unsigned char)line[i])) {
            return 0;
        }
    }

    return 1;
}

/**
 * Vérifie si une ligne est une réponse FTP (commence par 3 chiffres)
 * @param line: pointeur vers la ligne
 * @param len: longueur de la ligne
 * @return le code de réponse si valide, -1 sinon
 */
static int is_ftp_response(const char *line, int len) {
    if (len < 3) return -1;
    
    if (isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2])) {
        int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
        // Les codes FTP sont entre 100 et 599
        if (code >= 100 && code <= 599) {
            // Vérifier qu'après il y a un espace ou un tiret (pour multi-lignes)
            if (len == 3 || line[3] == ' ' || line[3] == '-')
                return code;
        }
    }
    return -1;
}


/**
 * Masque le mot de passe dans une commande PASS
 */
static void mask_ftp_password(char *line) {
    char cmd[32] = "", pass[128] = "";
    int matched = sscanf(line, "%31s %127s", cmd, pass);
    
    if (matched == 2 && strcasecmp(cmd, FTP_CMD_PASS) == 0) {
        snprintf(line, 255, "%s ****", cmd);
    }
}


/**
 * Parse et affiche une commande FTP
 */
static int parse_ftp_command(const u_char *packet, int length, int verbosity, int indent) {
    char line[512];
    int offset = 0;
    
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if (next < 0) return 0;
    
    mask_ftp_password(line);
    
    if (verbosity == 2) {
        print_indent(indent);
        printf("FTP Command: %s\n", line);
    } else if (verbosity == 3) {
        print_indent(indent);
        printf("[L7] FTP Command:\n");
        
        char cmd[16] = "";
        char args[256] = "";
        char *space = strchr(line, ' ');
        if (space) {
            int cmd_len = (int)(space - line);
            if (cmd_len < 16) {
                strncpy(cmd, line, (size_t)cmd_len);
                cmd[cmd_len] = '\0';
            }
            char *arg_start = space + 1;
            while (*arg_start == ' ') arg_start++;
            strncpy(args, arg_start, sizeof(args) - 1);
        } else {
            int max_cmd_len = (int)sizeof(cmd) - 1;
            int line_len = (int)strlen(line);
            int copy_len = (line_len < max_cmd_len) ? line_len : max_cmd_len;
            if (copy_len > 0) {
                memcpy(cmd, line, (size_t)copy_len);
            }
            cmd[copy_len] = '\0';
        }
        
        print_indent(indent + 2);
        printf("Command: %s\n", cmd);
        if (strlen(args) > 0) {
            print_indent(indent + 2);
            printf("Arguments: %s\n", args);
        }
    }
    
    return next;
}

/**
 * Parse et affiche une réponse FTP
 */
static int parse_ftp_response(const u_char *packet, int length, int verbosity, int indent) {
    char line[512];
    int offset = 0;
    int total_consumed = 0;
    int first_code = -1;
    int is_multi_line = 0;
    int expecting_continuation = 0;
    
    // FTP peut avoir des réponses multi-lignes (code suivi de '-' ou lignes avec espace)
    while (offset < length) {
        int next = text_extract_line(packet, offset, length - offset, line, sizeof(line));
        if (next < 0) break;
        
        // Vérifier si c'est une ligne de réponse FTP (commence par 3 chiffres)
        int code = is_ftp_response(line, (int)strlen(line));
        
        // Si c'est une ligne de réponse FTP
        if (code >= 0) {
            if (first_code < 0) first_code = code;
            
            // Extraire le message après le code
            char *msg_start = line + 3;
            while (*msg_start == ' ' || *msg_start == '-') msg_start++;
            
            // Vérifier si c'est une réponse multi-lignes (code suivi de '-')
            if (line[3] == '-') {
                is_multi_line = 1;
                expecting_continuation = 1;
            } else if (line[3] == ' ') {
                // Vérifier si la ligne suivante commence par un espace (pour FEAT, etc.)
                if (offset + next < length) {
                    char peek_line[512];
                    int peek_next = text_extract_line(packet, offset + next, length - offset - next, peek_line, sizeof(peek_line));
                    if (peek_next > 0 && peek_line[0] == ' ') {
                        // Ligne suivante commence par un espace, c'est une réponse multi-lignes
                        is_multi_line = 1;
                        expecting_continuation = 1;
                    }
                }
            }
            
            if (verbosity == 2) {
                print_indent(indent);
                printf("FTP Response: %d %s\n", code, msg_start);
            } else if (verbosity == 3) {
                if (total_consumed == 0) {
                    // Première ligne
                    print_indent(indent);
                    printf("FTP Response:\n");
                    print_indent(indent + 2);
                    printf("Code: %d\n", code);
                    print_indent(indent + 2);
                    printf("Message: %s\n", msg_start);
                } else {
                    // Ligne finale de la réponse multi-lignes
                    print_indent(indent + 2);
                    printf("  %s\n", msg_start);
                }
            }
            
            offset += next;
            total_consumed += next;
            
            // Si la ligne ne commence pas par le code suivi de '-', vérifier si on doit continuer
            if (line[3] != '-') {
                // Vérifier si la ligne suivante commence par un espace (pour FEAT, LIST, etc.)
                if (offset < length && expecting_continuation) {
                    char peek_line[512];
                    int peek_next = text_extract_line(packet, offset, length - offset, peek_line, sizeof(peek_line));
                    if (peek_next > 0 && peek_line[0] == ' ') {
                        // Ligne suivante commence par un espace, on continue
                        continue;
                    }
                }
                // Sinon, c'est la dernière ligne
                break;
            }
        } else if ((is_multi_line || expecting_continuation) && line[0] == ' ') {
            // Ligne de continuation qui commence par un espace (pour FEAT, LIST, NLST, HELP, etc.)
            char *content = line + 1; // Enlever le premier espace
            while (*content == ' ') content++; // Enlever les espaces supplémentaires
            
            if (verbosity == 2) {
                print_indent(indent);
                printf("FTP Response (continuation): %s\n", content);
            } else if (verbosity == 3) {
                print_indent(indent + 2);
                printf("  %s (continuation)\n", content);
            }
            
            offset += next;
            total_consumed += next;
            expecting_continuation = 1;
            
            // Continuer jusqu'à trouver une ligne qui commence par le code final
            if (offset < length) {
                char peek_line[512];
                int peek_next = text_extract_line(packet, offset, length - offset, peek_line, sizeof(peek_line));
                if (peek_next > 0) {
                    int next_code = is_ftp_response(peek_line, (int)strlen(peek_line));
                    if (next_code == first_code) {
                        // Ligne finale trouvée, on va la traiter au prochain tour
                        continue;
                    } else if (next_code < 0 && peek_line[0] == ' ') {
                        // Encore une ligne qui commence par un espace
                        continue;
                    }
                }
            }
        } else {
            // Plus de réponse FTP valide
            break;
        }
    }
    
    return total_consumed;
}

/**
 * Vérifie si une ligne est une continuation FTP (commence par un espace)
 * Utilisé pour détecter les lignes de continuation dans les réponses multi-lignes :
 */
static int is_ftp_continuation_line(const char *line, int len) {
    if (len < 2) return 0;
    // Une ligne de continuation commence par un espace
    if (line[0] == ' ') {
        // Vérifier que le reste est du texte ASCII imprimable (au moins 1 caractère)
        for (int i = 1; i < len && i < 100; i++) {
            if (line[i] == '\r' || line[i] == '\n') {
                // On a trouvé la fin de ligne, vérifier qu'il y a au moins un caractère imprimable
                return (i > 1);
            }
            if (!isprint(line[i]) && line[i] != '\t') return 0;
        }
        return 1;
    }
    return 0;
}

/**
 * Parse et affiche une ligne de continuation FTP (commence par un espace)
 * Ces lignes font partie d'une réponse multi-lignes (FEAT, LIST, NLST, HELP, etc.)
 */
static int parse_ftp_continuation(const u_char *packet, int length, int verbosity, int indent) {
    char line[512];
    int offset = 0;
    
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if (next < 0) return 0;
    
    // Vérifier que c'est bien une ligne de continuation
    if (!is_ftp_continuation_line(line, (int)strlen(line))) {
        return 0;
    }
    
    // Afficher la ligne de continuation (sans le premier espace pour la verbosité 2)
    char *content = line + 1; // Enlever le premier espace
    while (*content == ' ') content++; // Enlever les espaces supplémentaires
    
    if (verbosity == 2) {
        print_indent(indent);
        printf("FTP Response (continuation): %s\n", content);
    } else if (verbosity == 3) {
        print_indent(indent);
        printf("FTP Response:\n");
        print_indent(indent + 2);
        printf("  %s (continuation)\n", content);
    }
    
    return next;
}

/**
 * Fonction principale de parsing FTP
 */
int parse_ftp(const u_char *packet, int length, int verbosity, int indent) {
    if (length < 2) return 0;
    
    char line[512];
    int offset = 0;
    
    // Extraire la première ligne pour déterminer si c'est une commande ou une réponse
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if (next < 0) return 0;
    
    if (is_ftp_command(line, (int)strlen(line))) {
        return parse_ftp_command(packet, length, verbosity, indent);
    } else if (is_ftp_response(line, (int)strlen(line)) >= 0) {
        return parse_ftp_response(packet, length, verbosity, indent);
    } else if (is_ftp_continuation_line(line, (int)strlen(line))) {
        // Ligne de continuation (commence par un espace, comme les features dans FEAT)
        return parse_ftp_continuation(packet, length, verbosity, indent);
    }
    
    return 0;
}

/**
 * Résumé verbosité 1 pour FTP
 */
int ftp_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume) {
    if (caplen < offset_tcp_payload + 2) return 0;
    
    const u_char *payload = packet + offset_tcp_payload;
    int payload_len = caplen - offset_tcp_payload;
    
    char line[256];
    int next = text_extract_line(payload, 0, payload_len, line, sizeof(line));
    if (next < 0) return 0;
    
    // Masquer le mot de passe
    mask_ftp_password(line);
    
    if (is_ftp_command(line, (int)strlen(line))) {
        // Extraire juste la commande (sans arguments)
        char cmd[16] = "";
        sscanf(line, "%15s", cmd);
        if (can_append(resume, " | FTP CMD: ", RESUME_BUFFER_SIZE)) {
            safe_strcat(resume, " | FTP CMD: ", RESUME_BUFFER_SIZE);
            safe_strcat(resume, cmd, RESUME_BUFFER_SIZE);
        }
        return 1;
    } else {
        int code = is_ftp_response(line, (int)strlen(line));
        if (code >= 0) {
            char code_str[16];
            snprintf(code_str, sizeof(code_str), "%d", code);
            if (can_append(resume, " | FTP RESP: ", RESUME_BUFFER_SIZE)) {
                safe_strcat(resume, " | FTP RESP: ", RESUME_BUFFER_SIZE);
                safe_strcat(resume, code_str, RESUME_BUFFER_SIZE);
            }
            return 1;
        } else if (is_ftp_continuation_line(line, (int)strlen(line))) {
            // Ligne de continuation (commence par un espace)
            char *content = line + 1; // Enlever le premier espace
            while (*content == ' ') content++; // Enlever les espaces supplémentaires
            
            // Limiter la longueur pour l'affichage
            char cont_display[32] = "";
            int max_display_len = (int)sizeof(cont_display) - 1;
            // Copy min(strlen(content), max_display_len)
            int i = 0;
            while (i < max_display_len && content[i]) {
                cont_display[i] = content[i];
                i++;
            }
            cont_display[i] = '\0';
            
            if (can_append(resume, " | FTP CONT: ", RESUME_BUFFER_SIZE)) {
                safe_strcat(resume, " | FTP CONT: ", RESUME_BUFFER_SIZE);
                safe_strcat(resume, cont_display, RESUME_BUFFER_SIZE);
            }
            return 1;
        }
    }
    
    return 0;
}