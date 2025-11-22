#include "imap.h"
#include "../util/textutils.h"  // ← Utilise le module commun
#include "../hexdump.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

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
