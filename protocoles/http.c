#include "http.h"
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
    
    const char *methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"};
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
 * Trouve la fin de ligne (\r\n ou \n) dans les donnés
 * @param data: pointeur vers les données
 * @param offset: offset de départ pour la recherche
 * @param max_len: longueur maximale des données
 * @return offset de la fin de ligne, -1 si non trouvé
*/
static int find_line_end(const u_char *data, int offset, int max_len){
    for(int i = offset; i < max_len - 1; i++){
        if(data[i] == '\r' && data[i+1] == '\n')
            return i;
    }
    for (int i = offset; i < max_len; i++){
        if(data[i]== '\n')
            return i;
    }
    return -1;
}

/**
 * Extrait une ligne des données HTTP sans les terminaisons de ligne
 * @param data: pointeur vers les données
 * @param offset: offset de départ pour l'extraction
 * @param max_len: longueur maximale des données
 * @param out: buffer de sortie pour la ligne extraite
 * @param out_len: taille du buffer de sortie
 * @return nouvel offset après la ligne extraite, -1 en cas d'erreur
 */
static int extract_line(const u_char *data, int offset, int max_len, char *out, int out_len){
    int end = find_line_end(data, offset, max_len); // recherche de la fin de ligne
    if( end < 0)
        return -1;

    int line_len = end - offset; // longueur de la ligne sans CRLF
    if(line_len >= out_len) // vérifier la taille du buffer
        line_len = out_len - 1; 
    
    memcpy(out, data + offset, line_len); // copier la ligne dans le buffer de sortie
    out[line_len] = '\0';

    if(end + 1 < max_len && data[end] == '\r' && data[end+1] == '\n')
        return end + 2;
    return end + 1;
}

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
    int next =  extract_line(packet, offset, length, line, sizeof(line));
    if(next < 0)
        return 0;
    //  extraction methode, uri, version
    char method[16] = "", uri[256] = "", version[16] = "";
    sscanf(line, "%15s %255s %15s", method, uri, version);

    //verbosite 2
    if(verbosity == 2){
        for(int i = 0; i < indent; i++) printf(" ");
        printf("HTTP Request: %s %s %s\n", method, uri, version);
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
    offset = next;

    //parsing des headers
    if(verbosity == 3){
        for(int i = 0; i < indent; i++) printf(" ");
        printf("Headers:\n");
    }

    while(offset < length){
        next = extract_line(packet, offset, length, line, sizeof(line));
        if(next < 0)
            break;
        
        //ligne vide
        if(strlen(line) == 0){
            offset = next;
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

        offset = next;
    }

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
        
        if(is_text){
            // Afficher le texte directement
            for(int i = 0; i < indent; i++) printf(" ");
            printf("Content (text):\n");
            for(int i = 0; i < indent; i++) printf(" ");
            printf("---\n");
            fwrite(packet + offset, 1, body_len, stdout);
            printf("\n");
            for(int i = 0; i < indent; i++) printf(" ");
            printf("---\n");
        } else {
            // Afficher en hexdump pour données binaires
            print_hexdump(packet + offset, body_len);
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
    int next = extract_line(packet, offset, length, line, sizeof(line));
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
        next = extract_line(packet, offset, length, line, sizeof(line));
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
                
                if(is_text){
                    // Afficher le texte directement
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("Content (text):\n");
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("---\n");
                    fwrite(packet + offset, 1, actual_body_len, stdout);
                    printf("\n");
                    for(int i = 0; i < indent; i++) printf(" ");
                    printf("---\n");
                } else {
                    // Afficher en hexdump pour données binaires
                    print_hexdump(packet + offset, actual_body_len);
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
    
    // Ni requête ni réponse → afficher comme data en v2/v3
    if(verbosity == 2 && length > 0) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("HTTP Data: %d bytes\n", length);
        return length;
    }
    else if(verbosity == 3 && length > 0) {
        for(int i = 0; i < indent; i++) printf(" ");
        printf("HTTP Data: %d bytes\n", length);
        print_hexdump(packet, length);
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
    int end = find_line_end(http, 0, http_len);
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
    
        if(strlen(resume) + strlen(method) + strlen(uri) + 10 < 255) {
            strcat(resume, " | HTTP ");
            strcat(resume, method);
            strcat(resume, " ");
            strcat(resume, uri);
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
                int next_end = find_line_end(http, offset + 2, http_len);
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