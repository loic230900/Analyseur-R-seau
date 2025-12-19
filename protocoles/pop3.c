/**

Analyseur de messages POP3 (couche 7 - Application)
 * 
 * Ce module implémente le parsing des échanges POP3 conformément à la RFC 1939.
 * POP3 (Post Office Protocol version 3) permet la récupération des mails
 * depuis un serveur. Les mails sont téléchargés puis supprimés du serveur.
 * 
 * Caractéristiques :
 * - Protocole textuel basé sur des lignes (CRLF)
 * - Ports standard : 110 (POP3), 995 (POP3S/TLS)
 * - Réponses préfixées par +OK ou -ERR
 * 
 * Commandes POP3 principales :
 * - USER/PASS : Authentification
 * - STAT : Statistiques boîte aux lettres
 * - LIST : Liste des messages
 * - RETR : Récupération d'un message
 * - DELE : Marquage pour suppression
 * - QUIT : Fin de session et commit
 * - NOOP : Keep-alive
 * - RSET : Annulation des suppressions
 * 
 * Sécurité : masquage automatique des mots de passe (PASS ****).
 * 
 */

#include "pop3.h"
#include "../util/textutils.h"
#include "../hexdump.h"
#include "../util/safe_string.h"
#include "../util/display_constants.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/**
 * Masque le mot de passe dans une commande PASS
 * Format attendu: PASS password
 * Remplace password par ****
 * 
 * @param line: ligne à traiter 
 */
static void mask_pass_password(char *line) {
    // Vérifier si c'est une commande PASS
    char cmd[32] = "", pass[128] = "";
    
    // Essayer de parser 2 tokens : PASS password
    int matched = sscanf(line, "%31s %127s", cmd, pass);
    
    // Si on a bien 2 tokens et que la commande est PASS
    if (matched == 2 && strcasecmp(cmd, POP3_CMD_PASS) == 0) {
        // Reconstruire la ligne avec mot de passe masqué
        snprintf(line, 255, "%s ****", cmd);
    }
}

/**
 * Vérifie si une ligne est une commande POP3
 * @param line: pointeur vers la ligne
 * @param len: longueur de la ligne
 * @return 1 si c'est une commande POP3, 0 sinon
 */
static int is_pop3_command(const char *line, int len) {
    if (len < 3) return 0;
    
    const char *commands[] = {
        POP3_CMD_USER, POP3_CMD_PASS, POP3_CMD_APOP, POP3_CMD_STAT, POP3_CMD_LIST, 
        POP3_CMD_RETR, POP3_CMD_DELE, POP3_CMD_NOOP, POP3_CMD_RSET, POP3_CMD_QUIT, 
        POP3_CMD_TOP, POP3_CMD_UIDL, POP3_CMD_CAPA
    };
    int num_commands = sizeof(commands) / sizeof(commands[0]);
    
    for (int i = 0; i < num_commands; i++) {
        int cmd_len = (int)strlen(commands[i]);
        if (len >= cmd_len && strncasecmp(line, commands[i], (size_t)cmd_len) == 0) {
            // Vérifier qu'après la commande il y a un espace ou fin de ligne
            if (len == cmd_len || line[cmd_len] == ' ' || line[cmd_len] == '\r' || line[cmd_len] == '\n')
                return 1;
        }
    }
    return 0;
}

/**
 * Vérifie si une ligne est une réponse POP3 (commence par +OK ou -ERR)
 * @param line: pointeur vers la ligne
 * @param len: longueur de la ligne
 * @return 1 si +OK, -1 si -ERR, 0 sinon
 */
static int is_pop3_response(const char *line, int len) {
    if (len < 3) return 0;
    
    if (strncmp(line, POP3_RESP_OK, 3) == 0) {
        return 1;  // +OK
    } else if (strncmp(line, POP3_RESP_ERR, 4) == 0) {
        return -1; // -ERR
    }
    return 0;
}

/**
 * Parse et affiche une commande POP3
 * @param packet: pointeur vers le début de l'en-tête POP3
 * @param length: longueur totale des données POP3
 * @param verbosity: niveau de verbosité (2 ou 3)
 * @param indent: indentation pour l'affichage
 * @return nombre total d'octets traités
 */
static int parse_pop3_command(const u_char *packet, int length, int verbosity, int indent) {
    char line[512];
    int offset = 0;

    // Extraction de la ligne de commande
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if (next < 0)
        return 0;

    // Masquage du mot de passe
    mask_pass_password(line);

    // Verbosité 2 : affichage concis
    if (verbosity == 2) {
        print_indent(indent);
        printf("POP3 Command: %s\n", line);
    }
    // Verbosité 3 : affichage détaillé
    else if (verbosity == 3) {
        print_indent(indent);
        printf("[L7] POP3 Command:\n");
        
        // Extraire la commande et les arguments
        char cmd[16] = "";
        char args[256] = "";
        char *space = strchr(line, ' ');
        if (space) {
            int cmd_len = (int)(space - line);
            if (cmd_len < 16) {
                strncpy(cmd, line, (size_t)cmd_len);
                cmd[cmd_len] = '\0';
            }
            // Arguments après l'espace
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
    
    offset = next;
    return offset;
}

/**
 * Parse et affiche une réponse POP3
 * @param packet: pointeur vers le début de l'en-tête POP3
 * @param length: longueur totale des données POP3
 * @param verbosity: niveau de verbosité (2 ou 3)
 * @param indent: indentation pour l'affichage
 * @return nombre total d'octets traités
 */
static int parse_pop3_response(const u_char *packet, int length, int verbosity, int indent) {
    char line[512];
    int offset = 0;
    int consumed = 0;

    // Extraction de la ligne de réponse
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if (next < 0)
        return 0;

    // Extraire le statut et le message
    int is_ok = (strncmp(line, POP3_RESP_OK, 3) == 0);
    int is_err = (strncmp(line, POP3_RESP_ERR, 4) == 0);
    char message[256] = "";
    
    if (is_ok && strlen(line) > 3) {
        // Message après "+OK "
        char *msg_start = line + 3;
        while (*msg_start == ' ') msg_start++;
        int max_msg_len = (int)sizeof(message) - 1;
        int msg_src_len = (int)strlen(msg_start);
        int copy_len = (msg_src_len < max_msg_len) ? msg_src_len : max_msg_len;
        if (copy_len > 0) {
            memcpy(message, msg_start, (size_t)copy_len);
        }
        message[copy_len] = '\0';
    } else if (is_err && strlen(line) > 4) {
        // Message après "-ERR "
        char *msg_start = line + 4;
        while (*msg_start == ' ') msg_start++;
        int max_msg_len = (int)sizeof(message) - 1;
        int msg_src_len = (int)strlen(msg_start);
        int copy_len = (msg_src_len < max_msg_len) ? msg_src_len : max_msg_len;
        if (copy_len > 0) {
            memcpy(message, msg_start, (size_t)copy_len);
        }
        message[copy_len] = '\0';
    }

    // Verbosité 2
    if (verbosity == 2) {
        print_indent(indent);
        if (is_ok) {
            printf("POP3 Response: +OK");
        } else if (is_err) {
            printf("POP3 Response: -ERR");
        }
        if (strlen(message) > 0) {
            printf(" %s\n", message);
        } else {
            printf("\n");
        }
    }
    // Verbosité 3
    else if (verbosity == 3) {
        print_indent(indent);
        printf("POP3 Response:\n");
        
        print_indent(indent + 2);
        if (is_ok) {
            printf("Status: +OK\n");
        } else if (is_err) {
            printf("Status: -ERR\n");
        }
        
        if (strlen(message) > 0) {
            print_indent(indent + 2);
            printf("Message: %s\n", message);
        }
    }
    
    offset = next;
    consumed = offset;
    
    // Gestion des réponses multi-lignes (ex: LIST, RETR)
    // Les réponses multi-lignes se terminent par ".\r\n" seul sur une ligne
    if (is_ok) {
        // Chercher la fin de la réponse multi-ligne
        while (offset < length) {
            next = text_extract_line(packet, offset, length, line, sizeof(line));
            if (next < 0) break;
            
            // Si on trouve une ligne contenant uniquement ".", c'est la fin
            if (strcmp(line, ".") == 0) {
                offset = next;
                consumed = offset;
                break;
            }
            
            // Afficher les lignes intermédiaires en verbosité 3
            if (verbosity == 3) {
                print_indent(indent + 2);
                printf("  %s\n", line);
            }
            
            offset = next;
            consumed = offset;
            
            // Limiter pour éviter les boucles infinies
            if (consumed > length || consumed > 10000) break;
        }
    }
    
    return consumed;
}

/**
 * Fonction principale de parsing POP3
 */
int parse_pop3(const u_char *packet, int length, int verbosity, int indent) {
    if (length < 3) return 0; // Trop court pour POP3
    
    // Convertir le début en string pour analyse
    char header_start[512];
    int preview_len = (length < 511) ? length : 511;
    memcpy(header_start, packet, (size_t)preview_len);
    header_start[preview_len] = '\0';

    // Détection commande ou réponse
    if (is_pop3_command(header_start, preview_len)) {
        return parse_pop3_command(packet, length, verbosity, indent);
    } else if (is_pop3_response(header_start, preview_len) != 0) {
        return parse_pop3_response(packet, length, verbosity, indent);
    }
    
    // Cas particulier : données de mail (après RETR)
    // On peut détecter si c'est du texte ou si ça se termine par ".\r\n"
    if (verbosity == 3 && length > 0) {
        // Vérifier si c'est du texte imprimable
        int is_text = text_is_printable(packet, length > 200 ? 200 : length);
        
        if (is_text) {
            print_indent(indent);
            printf("POP3 Mail Data: %d bytes\n", length);
            
            // Chercher la fin du mail (ligne ".\r\n")
            int mail_end = -1;
            for (int i = 0; i < length - 2; i++) {
                if (packet[i] == '.' && packet[i+1] == '\r' && packet[i+2] == '\n') {
                    // Vérifier que c'est bien une ligne seule (précédée de \r\n)
                    if (i == 0 || (i > 0 && packet[i-1] == '\n')) {
                        mail_end = i + 3;
                        break;
                    }
                }
            }
            
            int display_len = (mail_end > 0 && mail_end < length) ? mail_end : (length > 500 ? 500 : length);
            
            print_indent(indent);
            printf("---\n");
            fwrite(packet, 1, (size_t)display_len, stdout);
            if (length > display_len) printf("\n... (truncated)");
            printf("\n");
            print_indent(indent);
            printf("---\n");
            
            return (mail_end > 0) ? mail_end : length;
        }
    }
    
    // Sinon, affichage générique pour verbosité 2
    if (verbosity == 2 && length > 0) {
        print_indent(indent);
        printf("POP3 Data: %d bytes\n", length);
        return length;
    }
    
    return 0;
}

/**
 * Résumé verbosité 1
 */
int pop3_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume) {
    if (caplen < offset_tcp_payload + 3)
        return 0;
    
    const u_char *pop3 = packet + offset_tcp_payload;
    int pop3_len = caplen - offset_tcp_payload;

    char line[128];
    int end = text_find_line_end(pop3, 0, pop3_len);
    if (end < 0 || end > 127)
        return 0;

    memcpy(line, pop3, (size_t)end);
    line[end] = '\0';
    mask_pass_password(line);

    // Commande POP3
    if (is_pop3_command(line, end)) {
        char cmd[16] = "";
        char args[64] = "";
        sscanf(line, "%15s %63[^\r\n]", cmd, args);
        
        char info[128];
        if (strlen(args) > 0) {
            snprintf(info, sizeof(info), " | POP3 %s %s", cmd, args);
        } else {
            snprintf(info, sizeof(info), " | POP3 %s", cmd);
        }
        
        safe_strcat(resume, info, RESUME_BUFFER_SIZE);
        return 1;
    }
    // Réponse POP3
    else {
        int resp_type = is_pop3_response(line, end);
        if (resp_type != 0) {
            char msg[64] = "";
            if (resp_type == 1 && end > 3) {
                // +OK
                char *msg_start = line + 3;
                while (*msg_start == ' ') msg_start++;
                int msg_len = (int)(end - (msg_start - line));
                if (msg_len > 63) msg_len = 63;
                if (msg_len > 0) {
                    memcpy(msg, msg_start, (size_t)msg_len);
                    msg[msg_len] = '\0';
                }
            } else if (resp_type == -1 && end > 4) {
                // -ERR
                char *msg_start = line + 4;
                while (*msg_start == ' ') msg_start++;
                int msg_len = (int)(end - (msg_start - line));
                if (msg_len > 63) msg_len = 63;
                if (msg_len > 0) {
                    memcpy(msg, msg_start, (size_t)msg_len);
                    msg[msg_len] = '\0';
                }
            }
            
            char info[128];
            if (resp_type == 1) {
                if (strlen(msg) > 0) {
                    snprintf(info, sizeof(info), " | POP3 +OK %s", msg);
                } else {
                    snprintf(info, sizeof(info), " | POP3 +OK");
                }
            } else {
                if (strlen(msg) > 0) {
                    snprintf(info, sizeof(info), " | POP3 -ERR %s", msg);
                } else {
                    snprintf(info, sizeof(info), " | POP3 -ERR");
                }
            }
            
            safe_strcat(resume, info, RESUME_BUFFER_SIZE);
            return 1;
        }
    }
    
    return 0;
}
