/**
 * @file telnet.c
 * @brief Analyseur de messages Telnet (couche 7 - Application)
 * 
 * Parsing Telnet conformément aux RFC 854-861.
 * Port standard : 23
 */

#include "telnet.h"
#include "util/textutils.h"
#include "hexdump.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* Table des commandes Telnet connues */
static const struct { unsigned char code; const char *name; } telnet_cmds[] = {
    {255, "IAC"}, {254, "DONT"}, {253, "DO"}, {252, "WONT"},
    {251, "WILL"}, {250, "SB"}, {240, "SE"}
};
#define TELNET_CMD_COUNT (sizeof(telnet_cmds) / sizeof(telnet_cmds[0]))

/* Obtient le nom d'une commande Telnet */
static const char *get_cmd_name(unsigned char cmd, char *buf, int buflen) {
    for (size_t i = 0; i < TELNET_CMD_COUNT; i++) {
        if (telnet_cmds[i].code == cmd) return telnet_cmds[i].name;
    }
    snprintf(buf, (size_t)buflen, "CMD_0x%02X", cmd);
    return buf;
}

/* Vérifie si commande nécessite une option (WILL/WONT/DO/DONT) */
static int cmd_needs_option(unsigned char cmd) {
    return (cmd >= 251 && cmd <= 254);
}

/* Filtre les séquences ANSI/escape codes */
static void filter_ansi(char *str) {
    if (!str) return;
    char *src = str, *dst = str;
    
    while (*src) {
        if (*src == '\x1b' && src[1]) {
            if (src[1] == '[') {
                /* CSI sequence: \x1b[...lettre */
                src += 2;
                while (*src && !(*src >= 'A' && *src <= 'Z') && 
                       !(*src >= 'a' && *src <= 'z') && 
                       *src != '@' && *src != '~' && *src != 'm') src++;
                if (*src) src++;
            } else if (src[1] == ']') {
                /* OSC sequence */
                src += 2;
                while (*src && *src != '\x07') {
                    if (*src == '\x1b' && src[1] == '\\') { src += 2; break; }
                    src++;
                }
                if (*src == '\x07') src++;
            } else if (src[1] == '(' || src[1] == ')') {
                src += 2;
                if (*src) src++;
            } else {
                src += 2;
            }
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

/* Vérifie si chaîne vide ou whitespace seulement */
static int is_empty(const char *str) {
    if (!str || !*str) return 1;
    for (const char *p = str; *p; p++)
        if (*p != ' ' && *p != '\t') return 0;
    return 1;
}

/* Trim trailing whitespace in-place */
static void trim_trailing(char *str) {
    int len = (int)strlen(str);
    while (len > 0 && (str[len-1] == ' ' || str[len-1] == '\t'))
        str[--len] = '\0';
}

/* Échappe les caractères de contrôle dans buf, retourne nb de chars écrits */
static int escape_controls(const u_char *data, int len, char *buf, int bufsize) {
    int rp = 0;
    for (int i = 0; i < len && rp < bufsize - 5; i++) {
        unsigned char c = data[i];
        if (c == '\r') { buf[rp++] = '\\'; buf[rp++] = 'r'; }
        else if (c == '\n') { buf[rp++] = '\\'; buf[rp++] = 'n'; }
        else if (c == '\t') { buf[rp++] = '\\'; buf[rp++] = 't'; }
        else if (isprint(c)) { buf[rp++] = (char)c; }
        else {
            char hex[5];
            snprintf(hex, sizeof(hex), "\\x%02X", c);
            for (int j = 0; hex[j] && rp < bufsize - 1; j++)
                buf[rp++] = hex[j];
        }
    }
    buf[rp] = '\0';
    return rp;
}

/* Extrait le texte imprimable d'un buffer */
static int extract_printable(const u_char *data, int len, char *buf, int bufsize) {
    int count = 0;
    for (int i = 0; i < len && count < bufsize - 1; i++) {
        unsigned char c = data[i];
        if (isprint(c)) buf[count++] = (char)c;
        else if (c == '\t') buf[count++] = ' ';
    }
    buf[count] = '\0';
    return count;
}

/* Direction string helper */
static const char *dir_str(int is_server_to_client) {
    return is_server_to_client ? "IN" : "OUT";
}

/* Parse une commande Telnet (IAC + cmd + option) */
static int parse_telnet_command(const u_char *packet, int length, int verbosity, int indent) {
    if (length < 1 || packet[0] != TELNET_IAC) return 0;
    
    if (length < 2) {
        if (verbosity >= 2) { print_indent(indent); printf("Telnet: IAC (incomplete)\n"); }
        return 1;
    }
    
    unsigned char cmd = packet[1];
    char cmd_buf[16];
    const char *cmd_name = get_cmd_name(cmd, cmd_buf, sizeof(cmd_buf));
    
    /* IAC IAC = literal 0xFF */
    if (cmd == TELNET_IAC) {
        if (verbosity == 3) { print_indent(indent); printf("Telnet: IAC IAC (literal 0xFF)\n"); }
        return 2;
    }
    
    /* Non-command byte after IAC */
    if (cmd < 240) {
        if (verbosity == 2) {
            print_indent(indent);
            printf("Telnet: IAC literal (0x%02X)\n", cmd);
        } else if (verbosity == 3) {
            print_indent(indent); printf("Telnet IAC Literal:\n");
            print_indent(indent + 2);
            printf("Value: 0x%02X ('%c')\n", cmd, isprint(cmd) ? cmd : '?');
        }
        return 2;
    }
    
    /* Verbosity 2: concis */
    if (verbosity == 2) {
        print_indent(indent);
        if (cmd_needs_option(cmd) && length >= 3) {
            printf("Telnet: %s %d\n", cmd_name, packet[2]);
            return 3;
        } else if (cmd == 250) { /* SB subnegotiation */
            int pos = 2;
            while (pos < length - 1) {
                if (packet[pos] == TELNET_IAC && packet[pos + 1] == 240) {
                    printf("Telnet: %s (subnegotiation, %d bytes)\n", cmd_name, pos + 2);
                    return pos + 2;
                }
                pos++;
            }
            printf("Telnet: %s (subnegotiation, incomplete)\n", cmd_name);
            return length;
        } else {
            printf("Telnet: %s\n", cmd_name);
            return 2;
        }
    }
    
    /* Verbosity 3: détaillé */
    if (verbosity == 3) {
        print_indent(indent); printf("[L7] Telnet Command:\n");
        print_indent(indent + 2); printf("IAC: 0xFF\n");
        print_indent(indent + 2); printf("Command: %s (0x%02X)\n", cmd_name, cmd);
        
        if (cmd_needs_option(cmd)) {
            print_indent(indent + 2);
            if (length >= 3) {
                printf("Option: %d (0x%02X)\n", packet[2], packet[2]);
                return 3;
            } else {
                printf("Option: (missing)\n");
                return 2;
            }
        } else if (cmd == 250) { /* SB */
            print_indent(indent + 2); printf("Subnegotiation Data:\n");
            int pos = 2;
            while (pos < length - 1) {
                if (packet[pos] == TELNET_IAC && packet[pos + 1] == 240) {
                    print_indent(indent + 4); printf("Length: %d bytes\n", pos - 2);
                    if (pos - 2 > 0 && pos - 2 <= 100) {
                        print_indent(indent + 4); printf("Content: ");
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
            print_indent(indent + 4); printf("(incomplete, no SE found)\n");
            return length;
        }
        return 2;
    }
    return 0;
}

/* Parse données texte Telnet */
static int parse_telnet_data(const u_char *packet, int length, int verbosity, int indent, int is_server) {
    if (length < 1) return 0;
    
    /* Trouver fin des données (avant IAC ou fin paquet) */
    int data_end = 0;
    while (data_end < length && packet[data_end] != TELNET_IAC) data_end++;
    if (data_end == 0) return 0;
    
    const char *dir = dir_str(is_server);
    
    if (verbosity == 2) {
        print_indent(indent);
        
        /* Essayer ligne complète */
        char line[512];
        int next = text_extract_line(packet, 0, data_end, line, sizeof(line));
        
        if (next > 0 && strlen(line) > 0) {
            filter_ansi(line);
            if (!is_empty(line)) {
                if ((int)strlen(line) > 70) { line[70] = '\0'; printf("Telnet %s: %s...\n", dir, line); }
                else printf("Telnet %s: %s\n", dir, line);
            }
        } else {
            /* Pas de ligne - extraire printables */
            char preview[256];
            int count = extract_printable(packet, data_end > 200 ? 200 : data_end, preview, sizeof(preview));
            filter_ansi(preview);
            
            if (!is_empty(preview) && count > 0) {
                if (count > 70) { preview[70] = '\0'; printf("Telnet %s: %s...\n", dir, preview); }
                else printf("Telnet %s: %s\n", dir, preview);
            } else if (data_end > 0) {
                /* Représentation des contrôles */
                char ctrl[128];
                int rp = escape_controls(packet, data_end > 30 ? 30 : data_end, ctrl, sizeof(ctrl));
                if (rp > 0) printf("Telnet %s: %s\n", dir, ctrl);
                else printf("Telnet %s: (%d bytes)\n", dir, data_end);
            }
        }
        return data_end;
    }
    
    if (verbosity == 3) {
        print_indent(indent); printf("Telnet Data:\n");
        
        char line[512];
        int next = text_extract_line(packet, 0, data_end, line, sizeof(line));
        
        if (next > 0 && strlen(line) > 0) {
            filter_ansi(line);
            print_indent(indent + 2); printf("Line: %s\n", line);
            print_indent(indent + 2); printf("Length: %d bytes\n", next);
        } else {
            char raw[512];
            int count = 0;
            for (int i = 0; i < data_end && count < 400; i++) {
                unsigned char c = packet[i];
                if (isprint(c)) raw[count++] = (char)c;
                else if (c == '\t') raw[count++] = '\t';
                else if (c == '\n' && count < 398) { raw[count++] = '\\'; raw[count++] = 'n'; }
                else if (c == '\r' && count < 398) { raw[count++] = '\\'; raw[count++] = 'r'; }
                else {
                    char hex[6];
                    snprintf(hex, sizeof(hex), "\\x%02X", c);
                    for (int j = 0; hex[j] && count < 400; j++) raw[count++] = hex[j];
                }
            }
            raw[count] = '\0';
            filter_ansi(raw);
            print_indent(indent + 2); printf("Content (%d bytes): %s\n", data_end, raw);
        }
        return data_end;
    }
    return data_end;
}

/* Fonction principale de parsing Telnet */
int parse_telnet(const u_char *packet, int length, int verbosity, int indent, uint16_t src_port, uint16_t dst_port) {
    if (length < 1) return 0;
    
    int offset = 0;
    int is_server = (src_port == TELNET_PORT);
    (void)dst_port;
    
    while (offset < length) {
        if (packet[offset] == TELNET_IAC) {
            int consumed = parse_telnet_command(packet + offset, length - offset, verbosity, indent);
            offset += (consumed > 0) ? consumed : 1;
        } else {
            int consumed = parse_telnet_data(packet + offset, length - offset, verbosity, indent, is_server);
            if (consumed > 0) {
                offset += consumed;
            } else {
                const char *dir = dir_str(is_server);
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

/* Résumé verbosité 1 pour Telnet */
int telnet_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume, uint16_t src_port, uint16_t dst_port) {
    if ((int)caplen < offset_tcp_payload) return 0;
    
    int payload_len = caplen - offset_tcp_payload;
    if (payload_len < 1) return 0;
    
    const u_char *payload = packet + offset_tcp_payload;
    int is_client = (dst_port == TELNET_PORT);
    const char *dir = is_client ? "OUT" : "IN";
    (void)src_port;
    
    int remaining = 255 - (int)strlen(resume);
    if (remaining <= 20) return 1;
    
    /* Commande IAC */
    if (payload[0] == TELNET_IAC) {
        snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet %s: cmd", dir);
        return 1;
    }
    
    /* Extraire contenu */
    char display[128] = "";
    char line[256];
    int next = text_extract_line(payload, 0, payload_len, line, sizeof(line));
    
    if (next > 0 && strlen(line) > 0) {
        filter_ansi(line);
        trim_trailing(line);
        if (!is_empty(line)) {
            strncpy(display, line, sizeof(display) - 1);
            display[sizeof(display) - 1] = '\0';
        }
    } else {
        int count = extract_printable(payload, payload_len > 100 ? 100 : payload_len, display, sizeof(display));
        filter_ansi(display);
        trim_trailing(display);
        (void)count;
    }
    
    /* Formater sortie */
    if (!is_empty(display)) {
        if ((int)strlen(display) > 35) {
            display[35] = '\0';
            snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet %s: %s...", dir, display);
        } else {
            snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet %s: %s", dir, display);
        }
    } else {
        snprintf(resume + strlen(resume), (size_t)remaining, " | Telnet %s: data", dir);
    }
    return 1;
}
