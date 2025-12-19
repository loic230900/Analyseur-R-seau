/**
 * Ce module implémente le parsing des échanges HTTP/1.x conformément
 * aux RFCs 7230-7235. Supporte les requêtes et réponses HTTP.
 * 
 * Port TCP : 80 (HTTP), 443 (HTTPS non analysé - chiffré)
 */

#include "http.h"
#include "../util/textutils.h"
#include "../hexdump.h"
#include "../util/safe_string.h"
#include "../util/display_constants.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// Déclarations forward des fonctions helper
static int find_natural_end(const u_char *data, int total_len, int max_display);

/**
 * Extraction et affichage d'un header HTTP spécifique dans une section de headers.
 * Parcourt les headers à partir de header_offset jusqu'à la fin (ligne vide)
 * et extrait la valeur du header recherché (comparaison insensible à la casse).
 * 
 * @param packet         Pointeur vers le début du paquet HTTP
 * @param header_offset  Offset du début de la section headers
 * @param length         Longueur totale disponible
 * @param header_name    Nom du header à rechercher (ex: "Host", "Content-Type")
 * @param output         Buffer où copier la valeur du header (sans espaces ni CRLF)
 * @param output_size    Taille du buffer de sortie
 * @return               Offset après la fin des headers (ligne vide), -1 si erreur
 */
static int extract_http_header(const u_char *packet, int header_offset, int length,
                                const char *header_name, char *output, size_t output_size) {
    char line[512];
    int offset = header_offset;
    output[0] = '\0';
    
    while(offset < length) {
        int next = text_extract_line(packet, offset, length, line, sizeof(line));
        if(next < 0) break;
        
        // Ligne vide = fin des headers
        if(strlen(line) == 0) {
            return offset;
        }
        
        // Parser "Header: Value"
        char *colon = strchr(line, ':');
        if(colon) {
            *colon = '\0';
            char *value = colon + 1;
            while(*value == ' ') value++;
            
            // Vérifier si c'est le header recherché
            if(strcasecmp(line, header_name) == 0) {
                // Enlever \r\n à la fin
                size_t value_len = strlen(value);
                while(value_len > 0 && (value[value_len-1] == '\r' || value[value_len-1] == '\n')) {
                    value[value_len-1] = '\0';
                    value_len--;
                }
                
                if(value_len > 0 && value_len < output_size - 1) {
                    strncpy(output, value, value_len);
                    output[value_len] = '\0';
                }
            }
        }
        
        offset = next;
    }
    
    return offset;
}

/**
 * Détecte si un buffer contient du texte imprimable.
 * Vérifie qu'au moins 80% des caractères sur les N premiers octets
 * sont imprimables (ou CRLF/TAB).
 * 
 * @param data    Pointeur vers les données à analyser
 * @param length  Longueur totale des données
 * @param sample  Nombre d'octets à échantillonner (512 recommandé)
 * @return        1 si texte, 0 si binaire
 */
static int is_printable_text(const u_char *data, int length, int sample) {
    int check_len = (length < sample) ? length : sample;
    int printable_count = 0;
    
    for(int i = 0; i < check_len; i++) {
        unsigned char c = data[i];
        if(isprint(c) || c == '\r' || c == '\n' || c == '\t') {
            printable_count++;
        }
    }
    
    // Au moins 80% de caractères imprimables
    return (printable_count * 100 / check_len) >= 80;
}

/* Affiche le corps HTTP (texte ou binaire) avec gestion intelligente de la truncation.
 * Détecte le type de contenu, trouve une fin naturelle (JSON/XML/ligne complète),
 * et affiche en texte brut ou hexdump selon le type.
 * 
 * @param packet    Pointeur vers le début du corps HTTP
 * @param length    Longueur totale du corps
 * @param indent    Indentation pour l'affichage
 * @param max_size  Taille maximale à afficher avant truncation
 */
static void display_http_body(const u_char *packet, int length, int indent, int max_size) {
    if(length <= 0) return;
    
    int is_text = is_printable_text(packet, length, 512);
    int display_len = find_natural_end(packet, length, max_size);
    
    if(is_text) {
        print_indent(indent);
        printf("Content (text):\n");
        print_indent(indent);
        printf("---\n");
        fwrite(packet, 1, (size_t)display_len, stdout);
        if(length > display_len) {
            printf("\n... (truncated, %d bytes total, showing first %d bytes)", length, display_len);
        }
        printf("\n");
        print_indent(indent);
        printf("---\n");
    } else {
        print_hexdump(packet, display_len);
        if(length > display_len) {
            print_indent(indent);
            printf("... (truncated, %d bytes total, showing first %d bytes)\n", length, display_len);
        }
    }
}

/**
 * Vérifie si une ligne est une requête HTTP.
 * Détecte les lignes commençant par une méthode HTTP valide
 * (caractères alphabétiques majuscules) suivie d'une URI.
 * 
 * @param line Pointeur vers le début de la ligne
 * @param len  Longueur de la ligne
 * @return     1 si requête HTTP, 0 sinon
 */
static int is_http_request(const char *line, int len) {
    // Minimum "GET / ..."
    if(len < 8) return 0;
    
    // Premier caractère doit être alphabétique et majuscule
    if(!isupper((unsigned char)line[0])) return 0;
    
    // Compter les caractères alphabétiques (longueur de la méthode)
    int method_len = 0;
    while(method_len < len && method_len < 20 && isalpha((unsigned char)line[method_len])) {
        method_len++;
    }
    
    // Méthode doit avoir 3-20 caractères (GET, OPTIONS, etc.)
    if(method_len < 3 || method_len > 20) return 0;
    
    // Vérifier que tous les caractères sont majuscules
    for(int i = 0; i < method_len; i++) {
        if(!isupper((unsigned char)line[i])) return 0;
    }
    
    // Après la méthode : un espace suivi de l'URI
    if(method_len < len) {
        if(line[method_len] != ' ') return 0;
        
        // Chercher le début de l'URI
        int uri_start = method_len + 1;
        while(uri_start < len && line[uri_start] == ' ') {
            uri_start++;
        }
        
        // L'URI doit commencer par / ou être un caractère imprimable
        if(uri_start < len && (line[uri_start] == '/' || isprint((unsigned char)line[uri_start]))) {
            return 1;
        }
    }
    
    return 0;
}

/**
 * Vérifie si une ligne est une réponse HTTP.
 * Détecte les lignes commençant par "HTTP/1.x".
 * 
 * @param line Pointeur vers le début de la ligne
 * @param len  Longueur de la ligne
 * @return     1 si réponse HTTP, -1 sinon
 */
static int is_http_response(const char *line, int len) {
    // Minimum "HTTP/1.x ..."
    if(len < 12) return -1;
    return (strncmp(line, "HTTP/1.", 7) == 0);
}

/** 
 * Trouve une fin naturelle pour l'affichage de contenu.
 * Cherche un point de coupure logique (fin de structure JSON/XML,
 * fin de ligne) pour éviter de tronquer au milieu d'un mot.
 * 
 * @param data        Pointeur vers les données
 * @param total_len   Longueur totale disponible
 * @param max_display Limite maximale souhaitée
 * @return            Longueur à afficher (peut être > max_display si message complet est proche)
 */
static int find_natural_end(const u_char *data, int total_len, int max_display) {
    // Si le message est complet et < limite, l'afficher en entier
    if(total_len <= max_display) {
        return total_len;
    }
    
    // Chercher une fin naturelle proche de la limite
    int search_start = max_display - NATURAL_END_SEARCH_BACK;
    if(search_start < 0) search_start = 0;
    int search_end = (total_len < max_display + NATURAL_END_SEARCH_FORWARD) ? total_len : max_display + NATURAL_END_SEARCH_FORWARD;
    
    // Détecter le type de contenu
    int is_json = (data[0] == '{' || data[0] == '[');
    int is_xml = (data[0] == '<');
    
    if(is_json) {
        // Pour JSON: compter les accolades/crochets pour trouver la fin complète
        char open_char = (data[0] == '{') ? '{' : '[';
        char close_char = (data[0] == '{') ? '}' : ']';
        int depth = 0;
        int in_string = 0; // Pour ignorer les caractères dans les strings JSON
        
        for(int i = 0; i < search_end && i < total_len; i++) {
            // Gérer les strings JSON (ignorer les caractères à l'intérieur)
            if(data[i] == '"' && (i == 0 || data[i-1] != '\\')) {
                in_string = !in_string;
                continue;
            }
            
            if(!in_string) {
                if(data[i] == open_char) {
                    depth++;
                } else if(data[i] == close_char) {
                    depth--;
                    // Si depth == 0, on a trouvé la fin complète du JSON
                    if(depth == 0) {
                        // Si c'est proche de max_display (dans les 500 bytes), afficher tout
                        if(i < max_display + 500) {
                            return i + 1; // Inclure le caractère de fermeture
                        }
                    }
                }
            }
            
            // Si on dépasse max_display et qu'on n'a pas trouvé de fin, chercher dans les 500 bytes suivants
            if(i >= max_display && depth > 0) {
                // Continuer à chercher jusqu'à search_end
                continue;
            }
        }
        
        // Si on a trouvé une fin complète mais après max_display + 500, tronquer à max_display
        if(depth > 0) {
            // Pas de fin complète trouvée dans la fenêtre de recherche
            return max_display;
        }
    } else if(is_xml) {
        // Pour XML: chercher la balise de fermeture
        for(int i = max_display; i < search_end && i < total_len; i++) {
            if(data[i] == '>' && i > 0 && data[i-1] == '/') {
                // Balise auto-fermante ou fin de balise
                return i + 1;
            }
        }
    } else {
        // Pour texte simple: chercher la fin d'une ligne complète
        for(int i = max_display; i < search_end && i < total_len; i++) {
            if(data[i] == '\n' || (data[i] == '\r' && i+1 < total_len && data[i+1] == '\n')) {
                return i + ((data[i] == '\r') ? 2 : 1);
            }
        }
    }
    
    // Si pas de fin naturelle trouvée, utiliser la limite
    return max_display;
}

/**
 * Parse et affiche une requête HTTP.
 * Extrait la request-line (méthode, URI, version), parse les headers
 * (notamment Host pour verbosité 2), et affiche le body si présent.
 * 
 * @param packet    Pointeur vers le début de l'en-tête HTTP
 * @param length    Longueur totale des données HTTP
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Indentation pour l'affichage
 * @return          Nombre total d'octets traités
 */
static int parse_http_request(const u_char *packet, int length, int verbosity, int indent) {
    char line[512]; 
    int offset = 0;

    // Parsing de la request line (GET /path HTTP....)
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if(next < 0) return 0;
    
    // Extraction méthode, URI, version
    char method[16] = "", uri[256] = "", version[16] = "";
    sscanf(line, "%15s %255s %15s", method, uri, version);
    offset = next;

    // Extraction du header Host (nécessaire pour v2 et v3)
    char host_header[256] = "";
    int headers_end = extract_http_header(packet, offset, length, "Host", host_header, sizeof(host_header));
    if(headers_end > 0) {
        offset = headers_end;
    }

    // Affichage selon verbosité
    if(verbosity == 2) {
        print_indent(indent);
        if(strlen(host_header) > 0) {
            printf("HTTP Request: %s %s %s [Host: %s]\n", method, uri, version, host_header);
        } else {
            printf("HTTP Request: %s %s %s\n", method, uri, version);
        }
    } else if(verbosity == 3) {
        print_indent(indent);
        printf("[L7] HTTP Request:\n");
        print_indent(indent);
        printf("      Method:  %s\n", method);
        print_indent(indent);
        printf("      URI:     %s\n", uri);
        print_indent(indent);
        printf("      Version: %s\n", version);
        
        // Affichage détaillé des headers
        print_indent(indent);
        printf("      Headers:\n");
        
        // Réparcourir les headers pour affichage complet
        int header_offset = next;
        while(header_offset < length) {
            int header_next = text_extract_line(packet, header_offset, length, line, sizeof(line));
            if(header_next < 0) break;
            if(strlen(line) == 0) break;
            
            char *colon = strchr(line, ':');
            if(colon) {
                *colon = '\0'; 
                char *value = colon + 1;
                while(*value == ' ') value++;
                
                print_indent(indent + 2);
                printf("%s %s\n", line, value);
            }
            header_offset = header_next;
        }
    }
    
    // Affichage du body (verbosité 3 uniquement)
    int body_len = length - offset;
    if(body_len > 0 && verbosity == 3) {
        print_indent(indent);
        printf("Body: %d bytes\n", body_len);
        display_http_body(packet + offset, body_len, indent, 2000);
    }
    
    return offset + body_len;
}

/**
 * Parse et affiche une réponse HTTP.
 * Extrait la status-line (version, code, message), parse les headers
 * (notamment Content-Length), et affiche le body si présent.
 * 
 * @param packet    Pointeur vers le début de l'en-tête HTTP
 * @param length    Longueur totale des données HTTP
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Indentation pour l'affichage
 * @return          Nombre total d'octets traités
 */
static int parse_http_response(const u_char *packet, int length, int verbosity, int indent) {
    char line[512];
    int offset = 0;

    // Parse status line (HTTP/1.1 200 OK)
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if(next < 0) return 0;

    // Extraction version, status code, phrase
    char version[16] = "", status_phrase[256] = "";
    int status_code = 0;

    char *space1 = strchr(line, ' ');
    if(space1) {
        *space1 = '\0';
        snprintf(version, sizeof(version), "%.*s", (int)sizeof(version) - 1, line);

        char *space2 = strchr(space1 + 1, ' ');
        if(space2) {
            *space2 = '\0';
            status_code = atoi(space1 + 1);
            snprintf(status_phrase, sizeof(status_phrase), "%.*s", (int)sizeof(status_phrase) - 1, space2 + 1);
        } else {
            status_code = atoi(space1 + 1);
        }
    }
    
    offset = next;

    // Extraction Content-Length pour dimensionner le body
    char content_len_str[32] = "";
    int headers_end = extract_http_header(packet, offset, length, "Content-Length", content_len_str, sizeof(content_len_str));
    int content_length = (strlen(content_len_str) > 0) ? atoi(content_len_str) : -1;
    if(headers_end > 0) {
        offset = headers_end;
    }

    // Affichage selon verbosité
    if(verbosity == 2) {
        print_indent(indent);
        printf("HTTP Response: %s %d %s\n", version, status_code, status_phrase);
    } else if(verbosity == 3) {
        print_indent(indent);
        printf("HTTP Response:\n");
        print_indent(indent + 2);
        printf("Version:     %s\n", version);
        print_indent(indent + 2);
        printf("Status Code: %d\n", status_code);
        print_indent(indent + 2);
        printf("Status:      %s\n", status_phrase);
        
        // Affichage détaillé des headers
        print_indent(indent);
        printf("Headers:\n");
        
        int header_offset = next;
        while(header_offset < length) {
            int header_next = text_extract_line(packet, header_offset, length, line, sizeof(line));
            if(header_next < 0) break;
            if(strlen(line) == 0) break;
            
            char *colon = strchr(line, ':');
            if(colon) {
                *colon = '\0';
                char *value = colon + 1;
                while(*value == ' ') value++;
                
                print_indent(indent + 2);
                printf("%s: %s\n", line, value);
            }
            header_offset = header_next;
        }
    }
    
    // Affichage du body (verbosité 3 uniquement)
    int body_len = (content_length >= 0) ? content_length : (length - offset);
    if(body_len > 0 && verbosity == 3 && offset < length) {
        int actual_body_len = (offset + body_len <= length) ? body_len : (length - offset);
        if(actual_body_len > 0) {
            print_indent(indent);
            printf("Body: %d bytes\n", body_len);
            display_http_body(packet + offset, actual_body_len, indent, 2000);
        }
    }
    
    return offset + body_len;
}

/**
 * Fonction principale de parsing HTTP.
 * Détecte automatiquement le type (requête/réponse/body fragmenté)
 * et route vers le parser approprié.
 * 
 * @param packet    Pointeur vers le début des données HTTP
 * @param length    Longueur des données HTTP
 * @param verbosity Niveau de verbosité (2 ou 3)
 * @param indent    Indentation pour l'affichage
 * @return          Nombre d'octets consommés
 */
int parse_http(const u_char *packet, int length, int verbosity, int indent) {
    // Vérification longueur minimale
    if(length < 10) return 0;
    
    // Convertir début en string pour analyse
    char header_start[512];
    int preview_len = (length < 511) ? length : 511;
    memcpy(header_start, packet, (size_t)preview_len);
    header_start[preview_len] = '\0';

    // Détection requête ou réponse
    if(is_http_request(header_start, preview_len)) {
        return parse_http_request(packet, length, verbosity, indent);
    } else if(is_http_response(header_start, preview_len)) {
        return parse_http_response(packet, length, verbosity, indent);
    }
    
    // Ni requête ni réponse → body fragmenté ou continuation
    if(length > 0) {
        if(verbosity == 2) {
            print_indent(indent);
            printf("HTTP Body (fragmented): %d bytes\n", length);
        } else if(verbosity == 3) {
            print_indent(indent);
            printf("HTTP Body (fragmented): %d bytes\n", length);
            display_http_body(packet, length, indent, 2000);
        }
        return length;
    }
    
    return 0;
}

// Résumé verbosité 1 pour HTTP

int http_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume) {
    // Vérification longueur minimale
    if(caplen < offset_tcp_payload + 10) return 0;
    
    const u_char *http = packet + offset_tcp_payload;
    int http_len = caplen - offset_tcp_payload;

    // Extraction première ligne
    char line[128];
    int end = text_find_line_end(http, 0, http_len);
    if(end < 0 || end > 127) {
        // Pas de ligne valide → body/data seul
        if(http_len > 0) {
            char data_info[64];
            snprintf(data_info, sizeof(data_info), " | HTTP [DATA %d bytes]", http_len);
            safe_strcat(resume, data_info, RESUME_BUFFER_SIZE);
            return 1;
        }
        return 0;
    }

    memcpy(line, http, (size_t)end);
    line[end] = '\0';

    // Cas 1 : Requête HTTP
    if(is_http_request(line, end)) {
        char method[16] = "", uri[64] = "";
        sscanf(line, "%15s %63s", method, uri);
        
        // Extraction header Host via helper
        char host[128] = "";
        extract_http_header(http, end + 2, http_len, "Host", host, sizeof(host));
        
        // Construction résumé
        char http_str[256];
        if(strlen(host) > 0) {
            snprintf(http_str, sizeof(http_str), " | HTTP %s %s [Host: %s]", method, uri, host);
        } else {
            snprintf(http_str, sizeof(http_str), " | HTTP %s %s", method, uri);
        }
        safe_strcat(resume, http_str, RESUME_BUFFER_SIZE);
        return 1;
    }
    
    // Cas 2 : Réponse HTTP
    if(is_http_response(line, end)) {
        int code = 0;
        char reason[64] = "";
        
        // Parse "HTTP/1.1 200 OK"
        if(sscanf(line, "HTTP/%*s %d %63[^\r\n]", &code, reason) >= 1 && code > 0) {
            // Extraction Content-Type via helper
            char content_type[128] = "";
            extract_http_header(http, end + 2, http_len, "Content-Type", content_type, sizeof(content_type));
            
            // Simplification type MIME
            const char *type_marker = "";
            if(strlen(content_type) > 0) {
                if(strstr(content_type, "json")) {
                    type_marker = " [JSON]";
                } else if(strstr(content_type, "html")) {
                    type_marker = " [HTML]";
                } else if(strstr(content_type, "text")) {
                    type_marker = " [TEXT]";
                } else if(strstr(content_type, "image")) {
                    type_marker = " [IMG]";
                }
            }
            
            // Construction résumé
            char code_str[128];
            if(strlen(reason) > 0) {
                snprintf(code_str, sizeof(code_str), " | HTTP %d %s%s", code, reason, type_marker);
            } else {
                snprintf(code_str, sizeof(code_str), " | HTTP %d%s", code, type_marker);
            }
            safe_strcat(resume, code_str, RESUME_BUFFER_SIZE);
            return 1;
        }
    }
    
    // Cas 3 : Ni requête ni réponse → body/data
    if(http_len > 0) {
        char data_info[64];
        snprintf(data_info, sizeof(data_info), " | HTTP [DATA %d bytes]", http_len);
        safe_strcat(resume, data_info, RESUME_BUFFER_SIZE);
        return 1;
    }
    
    return 0;
}