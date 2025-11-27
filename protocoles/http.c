#include "http.h"
#include "../util/textutils.h"
#include "../hexdump.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>


/**
* Verifie si une ligne commence par une methode http
* @param line: pointeur vers le debut de la ligne
* @param len: longueur de la ligne
* @return 1 si c'est une requete http, 0 sinon
*/
static int is_http_request(const char *line, int len){
    if(len < 8) // minimum "GET / ..."
        return 0;
    
    const char *methods[] = {
        HTTP_METHOD_GET, HTTP_METHOD_POST, HTTP_METHOD_PUT, 
        HTTP_METHOD_DELETE, HTTP_METHOD_HEAD, HTTP_METHOD_OPTIONS
    };
    int num_methods = sizeof(methods) / sizeof(methods[0]);
    for(int i = 0; i < num_methods; i++){
        int method_len = strlen(methods[i]);
        if(len >= method_len && strncmp(line, methods[i], method_len) == 0){
            return 1;
        }
    }
    return 0;
}

/**
 * Verifie si une ligne commence par une reponse http
 * @param line: pointeur vers le debut de la ligne
 * @param len: longueur de la ligne
 * @return 1 si c'est une reponse http, -1 sinon
*/
static int is_http_response(const char *line, int len){
    if (len < 12) // minimum "HTTP/1.x ..."
        return -1;
    return (strncmp(line, "HTTP/1.", 7) == 0);
}

/**
 * Trouve une fin naturelle d'un message textuel (JSON, XML, etc.) pour éviter de couper
 * @param data: pointeur vers les données
 * @param total_len: longueur totale disponible
 * @param max_display: limite maximale souhaitée
 * @return longueur à afficher (peut être > max_display si message complet est proche)
 */
static int find_natural_end(const u_char *data, int total_len, int max_display) {
    // Si le message est complet et < limite, l'afficher en entier
    if(total_len <= max_display) {
        return total_len;
    }
    
    // Chercher une fin naturelle proche de la limite
    int search_start = max_display - 200; // Chercher dans les 200 derniers bytes avant la limite
    if(search_start < 0) search_start = 0;
    int search_end = (total_len < max_display + 500) ? total_len : max_display + 500;
    
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

/* Helpers de parsing de lignes déplacés dans textutils.c */

/**
 * Parse et affiche une requete HTTP
 * @param packet: pointeur vers le debut de l'en-tete HTTP
 * @param length: longueur totale des données HTTP
 * @param verbosity: niveau de verbosité (2 ou 3)
 * @param indent: indentation pour l'affichage
 * @return nombre total d'octets traités
 */
static int parse_http_request(const u_char *packet, int length, int verbosity, int indent){
    char line[512]; 
    int offset = 0;

    //parsing de la request line (GET /path HTTP....)
    int next =  text_extract_line(packet, offset, length, line, sizeof(line));
    if(next < 0)
        return 0;
    //  extraction methode, uri, version
    char method[16] = "", uri[256] = "", version[16] = "";
    sscanf(line, "%15s %255s %15s", method, uri, version);

    offset = next;

    //parsing des headers pour extraire Host (nécessaire pour v2 et v3)
    char host_header[256] = "";
    int header_offset = offset;
    int header_next;
    
    while(header_offset < length){
        header_next = text_extract_line(packet, header_offset, length, line, sizeof(line));
        if(header_next < 0)
            break;
        
        //ligne vide = fin des headers
        if(strlen(line) == 0){
            break;
        }

        char *colon = strchr(line, ':');
        if(colon){
            *colon = '\0'; 
            char *value = colon + 1;
            while(*value == ' ')
                value ++;
            
            // Extraire Host header
            if(strcasecmp(line, "Host") == 0) {
                // Enlever \r\n à la fin
                int host_len = strlen(value);
                while(host_len > 0 && (value[host_len-1] == '\r' || value[host_len-1] == '\n')) {
                    value[host_len-1] = '\0';
                    host_len--;
                }
                if(host_len > 0 && host_len < 255) {
                    strncpy(host_header, value, host_len);
                    host_header[host_len] = '\0';
                }
            }
        }

        header_offset = header_next;
    }

    //verbosite 2
    if(verbosity == 2){
        for(int i = 0; i < indent; i++) printf(" ");
        if(strlen(host_header) > 0) {
            printf("HTTP Request: %s %s %s [Host: %s]\n", method, uri, version, host_header);
        } else {
        printf("HTTP Request: %s %s %s\n", method, uri, version);
        }
    }
    else if (verbosity == 3){ // verbosite 3
        for(int  i=0; i < indent; i++ ) printf(" ");
        printf("HTTP Request:\n");

        for(int i = 0; i < indent +2; i++) printf(" ");
        printf("Method:  %s\n",method);

        for(int i = 0; i < indent + 2; i++) printf(" ");
        printf("URI:     %s\n", uri);

        for(int i = 0; i < indent + 2; i++) printf(" ");
        printf("Version: %s\n", version);
    }

    //parsing des headers (réafficher pour verbosité 3)
    if(verbosity == 3){
        for(int i = 0; i < indent; i++) printf(" ");
        printf("Headers:\n");
    }

    // Réparcourir les headers pour l'affichage détaillé en v3
    header_offset = offset;
    while(header_offset < length){
        header_next = text_extract_line(packet, header_offset, length, line, sizeof(line));
        if(header_next < 0)
            break;
        
        //ligne vide
        if(strlen(line) == 0){
            offset = header_offset;
            break;
        }

        char *colon = strchr(line, ':');
        if(colon){
            *colon = '\0'; 
            char *value = colon + 1;
            while(*value == ' ')
                value ++;

            if(verbosity == 3){
                for(int i = 0; i < indent + 2;i++)printf(" ");
                printf("%s %s\n", line, value);
            }
        }

        header_offset = header_next;
    }
    
    // Mettre à jour offset pour le body
    offset = header_offset;

    //body
    int body_len = length - offset;

    if(body_len > 0 && verbosity == 3){
        for(int i = 0; i < indent; i++) printf(" ");
        printf("Body: %d bytes\n", body_len);

        // Vérifier si le body est du texte imprimable
        int is_text = 1;
        for(int i = 0; i < body_len && i < 512; i++){
            unsigned char c = packet[offset + i];
            if(!isprint(c) && c != '\r' && c != '\n' && c != '\t'){
                is_text = 0;
                break;
            }
        }
        
        // Limiter l'affichage intelligemment (ne pas couper un message complet)
        int display_len = find_natural_end(packet + offset, body_len, 2000);
        
        if(is_text){
            // Afficher le texte directement
            for(int i = 0; i < indent; i++) printf(" ");
            printf("Content (text):\n");
            for(int i = 0; i < indent; i++) printf(" ");
            printf("---\n");
            fwrite(packet + offset, 1, display_len, stdout);
            if(body_len > display_len) {
                printf("\n... (truncated, %d bytes total, showing first %d bytes)", body_len, display_len);
            }
            printf("\n");
            for(int i = 0; i < indent; i++) printf(" ");
            printf("---\n");
        } else {
            // Afficher en hexdump pour données binaires (limité aussi)
            print_hexdump(packet + offset, display_len);
            if(body_len > display_len) {
                for(int i = 0; i < indent; i++) printf(" ");
                printf("... (truncated, %d bytes total, showing first %d bytes)\n", body_len, display_len);
            }
        }
    }
    return offset + body_len;
}

/**
 * Parse et affiche une reponse HTTP
 * @param packet: pointeur vers le debut de l'en-tete HTTP
 * @param length: longueur totale des données HTTP
 * @param verbosity: niveau de verbosité (2 ou 3)
 * @param indent: indentation pour l'affichage
 * @return nombre total d'octets traités
 */
static int parse_http_response(const u_char *packet, int length, int verbosity, int indent){
    char line[512];
    int offset = 0;

    //parse status (HTTP/1.1 .....)
    int next = text_extract_line(packet, offset, length, line, sizeof(line));
    if(next < 0) 
        return 0;

    // extraction version, status code, phrase
    char version[16] = "", status_phrase[256] = "";
    int status_code = 0;

    //parsing 
    char *space1 = strchr(line, ' ');
    if(space1){
        *space1 = '\0';
        strncpy(version, line, sizeof(version) - 1);

        char *space2 = strchr(space1 + 1, ' ');
        if(space2) {
            *space2 = '\0';
            status_code = atoi(space1 + 1);
            strncpy(status_phrase, space2 +1, sizeof(status_phrase) - 1);
        }
        else {
            status_code = atoi(space1 + 1);
        }
    }
    if (verbosity == 2) { //verbosite 2 
        for(int i = 0; i < indent; i++) printf(" ");
        printf("HTTP Response: %s %d %s\n", version, status_code, status_phrase);
    }
    else if(verbosity == 3) { //vebosite 3
        for(int i = 0; i < indent; i++) printf(" ");
        printf("HTTP Response:\n");
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Version:     %s\n", version);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Status Code: %d\n", status_code);
        
        for(int i = 0; i < indent+2; i++) printf(" ");
        printf("Status:      %s\n", status_phrase);
    }
    offset = next;

    //parse headers
    if(verbosity == 3) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("Headers:\n");
    }
    
    int content_length = -1;
    
    while(offset < length) {
        next = text_extract_line(packet, offset, length, line, sizeof(line));
        if(next < 0) break;
        
        if(strlen(line) == 0) {
            offset = next;
            break;
        }
        
        char *colon = strchr(line, ':');
        if(colon) {
            *colon = '\0';
            char *value = colon + 1;
            while(*value == ' ') value++;
            
            // Extraire Content-Length pour savoir taille du body
            if(strcasecmp(line, "Content-Length") == 0) {
                content_length = atoi(value);
            }
            
            if(verbosity == 3) {
                for(int i = 0; i < indent+2; i++) printf(" ");
                printf("%s: %s\n", line, value);
            }
        }
        
        offset = next;
    }
    
    // Body
    int body_len = (content_length >= 0) ? content_length : (length - offset);
    if(body_len > 0 && verbosity == 3) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("Body: %d bytes\n", body_len);
        
        if(offset < length) {
            int actual_body_len = (offset + body_len <= length) ? body_len : (length - offset);
            if(actual_body_len > 0) {
                // Vérifier si le body est du texte imprimable
                int is_text = 1;
                for(int i = 0; i < actual_body_len && i < 512; i++){
                    unsigned char c = packet[offset + i];
                    if(!isprint(c) && c != '\r' && c != '\n' && c != '\t'){
                        is_text = 0;
                        break;
                    }
                }
                
                // Limiter l'affichage intelligemment (ne pas couper un message complet)
                int display_len = find_natural_end(packet + offset, actual_body_len, 2000);
                
                if(is_text){
                    // Afficher le texte directement
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("Content (text):\n");
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("---\n");
                    fwrite(packet + offset, 1, display_len, stdout);
                    if(actual_body_len > display_len) {
                        printf("\n... (truncated, %d bytes total, showing first %d bytes)", actual_body_len, display_len);
                    }
                    printf("\n");
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("---\n");
                } else {
                    // Afficher en hexdump pour données binaires (limité aussi)
                    print_hexdump(packet + offset, display_len);
                    if(actual_body_len > display_len) {
                        for(int i = 0; i < indent; i++) printf(" ");
                        printf("... (truncated, %d bytes total, showing first %d bytes)\n", actual_body_len, display_len);
                    }
                }
            }
        }
    }
    
    return offset + body_len;
}

/*Fonction principale */
int parse_http(const u_char *packet, int length, int verbosity, int indent) {
    if(length < 10) return 0; // Trop court pour HTTP
    
    //convertir  debut en string pour analyse
    char header_start[512];
    int preview_len = (length < 511) ? length : 511;
    memcpy(header_start, packet, preview_len);
    header_start[preview_len] = '\0';

    //detection request ou response
    if(is_http_request(header_start, preview_len)){
        return parse_http_request(packet, length, verbosity, indent);
    }
    else if(is_http_response(header_start, preview_len)){
        return parse_http_response(packet, length, verbosity, indent);
    }
    
    // Ni requête ni réponse → probablement du body fragmenté
    // Détecter si c'est du JSON/text pour l'afficher intelligemment
    if(verbosity == 2 && length > 0) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("HTTP Body (fragmented): %d bytes\n", length);
        return length;
    }
    else if(verbosity == 3 && length > 0) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("HTTP Body (fragmented): %d bytes\n", length);
        
        // Vérifier si c'est du texte/JSON (commence souvent par { ou [)
        int is_text = 1;
        int check_len = (length > 512) ? 512 : length;
        for(int i = 0; i < check_len; i++) {
            unsigned char c = packet[i];
            if(!isprint(c) && c != '\r' && c != '\n' && c != '\t' && c != ' ') {
                is_text = 0;
                break;
            }
        }
        
        // Limiter l'affichage intelligemment (ne pas couper un message complet)
        int display_len = find_natural_end(packet, length, 2000);
        
        if(is_text && (packet[0] == '{' || packet[0] == '[' || packet[0] == '<')) {
            // Probablement JSON/XML/text
            for(int i = 0; i < indent; i++) printf(" ");
            printf("Content (text):\n");
            for(int i = 0; i < indent; i++) printf(" ");
            printf("---\n");
            fwrite(packet, 1, display_len, stdout);
            if(length > display_len) {
                printf("\n... (truncated, %d bytes total, showing first %d bytes)", length, display_len);
            }
            printf("\n");
            for(int i = 0; i < indent; i++) printf(" ");
            printf("---\n");
        } else {
            // Afficher en hexdump
            print_hexdump(packet, display_len);
            if(length > display_len) {
                for(int i = 0; i < indent; i++) printf(" ");
                printf("... (truncated, %d bytes total, showing first %d bytes)\n", length, display_len);
            }
        }
        return length;
    }
    
    return 0;
}

/*resume verbosite 1*/
int http_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume){
    if(caplen < offset_tcp_payload + 10) //trop court pour HTTP
        return 0;
    
    const u_char *http = packet + offset_tcp_payload;
    int http_len = caplen - offset_tcp_payload;

    char line[128];
    int end = text_find_line_end(http, 0, http_len);
    if (end < 0 || end > 127) {
        // Pas de ligne valide trouvée → probablement du body/data seul
        if(http_len > 0) {
            char data_info[64];
            snprintf(data_info, sizeof(data_info), " | HTTP [DATA %d bytes]", http_len);
            if(strlen(resume) + strlen(data_info) < 255) {
                strcat(resume, data_info);
            }
            return 1;
        }
        return 0;
    }

    memcpy(line, http, end);
    line[end] = '\0';

    //request 
    if(is_http_request(line, end)) {
        char method[16] = "", uri[64] = "";
        sscanf(line, "%15s %63s", method, uri);
    
        // Chercher le header Host:
        char host[128] = "";
        int offset = end;
        while(offset < http_len) {
            int next_end = text_find_line_end(http, offset + 2, http_len);
            if(next_end < 0) break;
            
            int line_len = next_end - (offset + 2);
            if(line_len <= 0) break; // fin des headers
            if(line_len > 127) line_len = 127;
            
            char header[128];
            memcpy(header, http + offset + 2, line_len);
            header[line_len] = '\0';
            
            // Host header
            if(strncasecmp(header, "Host:", 5) == 0) {
                char *value = header + 5;
                while(*value == ' ') value++;
                // Enlever \r\n à la fin
                int host_len = strlen(value);
                while(host_len > 0 && (value[host_len-1] == '\r' || value[host_len-1] == '\n')) {
                    value[host_len-1] = '\0';
                    host_len--;
                }
                if(host_len > 0 && host_len < 127) {
                    strncpy(host, value, host_len);
                    host[host_len] = '\0';
                }
                break; // Host trouvé, on peut arrêter
            }
            offset = next_end;
        }
        
        // Construire le résumé avec Host si disponible
        if(strlen(host) > 0) {
            char http_str[256];
            snprintf(http_str, sizeof(http_str), " | HTTP %s %s [Host: %s]", method, uri, host);
            if(strlen(resume) + strlen(http_str) < 255) {
                strcat(resume, http_str);
            } else {
                // Fallback sans Host si trop long
                if(strlen(resume) + strlen(method) + strlen(uri) + 10 < 255) {
                    strcat(resume, " | HTTP ");
                    strcat(resume, method);
                    strcat(resume, " ");
                    strcat(resume, uri);
                }
            }
        } else {
            // Pas de Host header trouvé
        if(strlen(resume) + strlen(method) + strlen(uri) + 10 < 255) {
            strcat(resume, " | HTTP ");
            strcat(resume, method);
            strcat(resume, " ");
            strcat(resume, uri);
            }
        }
        return 1;
    }
    // Response
    else if(is_http_response(line, end)) {
        int code = 0;
        char reason[64] = "";
        
        // Parse: "HTTP/1.1 200 OK"
        if(sscanf(line, "HTTP/%*s %d %63[^\r\n]", &code, reason) >= 1 && code > 0) {
            char code_str[128];
            if(strlen(reason) > 0) {
                snprintf(code_str, sizeof(code_str), " | HTTP %d %s", code, reason);
            } else {
                snprintf(code_str, sizeof(code_str), " | HTTP %d", code);
            }
            
            // Chercher Content-Type et Content-Length dans les headers
            int offset = end;
            while(offset < http_len) {
                int next_end = text_find_line_end(http, offset + 2, http_len);
                if(next_end < 0) break;
                
                int line_len = next_end - (offset + 2);
                if(line_len <= 0) break; // fin des headers
                if(line_len > 100) line_len = 100;
                
                char header[128];
                memcpy(header, http + offset + 2, line_len);
                header[line_len] = '\0';
                
                // Content-Type
                if(strncasecmp(header, "Content-Type:", 13) == 0) {
                    char *value = header + 13;
                    while(*value == ' ') value++;
                    
                    // Extraire type principal (avant ;)
                    char type[32];
                    int i = 0;
                    while(*value && *value != ';' && *value != '\r' && i < 30) {
                        type[i++] = *value++;
                    }
                    type[i] = '\0';
                    
                    // Simplifier les types courants
                    if(strstr(type, "json")) {
                        strcat(code_str, " [JSON]");
                    } else if(strstr(type, "html")) {
                        strcat(code_str, " [HTML]");
                    } else if(strstr(type, "text")) {
                        strcat(code_str, " [TEXT]");
                    } else if(strstr(type, "image")) {
                        strcat(code_str, " [IMG]");
                    }
                    break; // trouvé
                }
                offset = next_end;
            }
            
            if(strlen(resume) + strlen(code_str) < 255) {
                strcat(resume, code_str);
            }
            return 1;
        }
    }
    
    // Si on arrive ici : ligne trouvée mais ni requête ni réponse -> body/data
    if(http_len > 0) {
        char data_info[64];
        snprintf(data_info, sizeof(data_info), " | HTTP [DATA %d bytes]", http_len);
        if(strlen(resume) + strlen(data_info) < 255) {
            strcat(resume, data_info);
        }
        return 1;
    }
    
    return 0;
}