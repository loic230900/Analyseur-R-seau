#include "imap.h"
#include "../hexdump.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * Trouve la fin de ligne (\r\n ou \n) dans les données
 * @param data: pointeur vers les données
 * @param offset: offset de départ pour la recherche
 * @param max_len: longueur maximale des données
 * @return offset de la fin de ligne, -1 si non trouvé
 */