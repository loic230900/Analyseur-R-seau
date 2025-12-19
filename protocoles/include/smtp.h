/**
 * Définitions pour l'analyse SMTP
 * 
 * Définitions et prototypes pour le parsing SMTP (RFC 5321).
 * Ports TCP : 25 (SMTP), 587 (submission), 465 (SMTPS).
 * 
 */

#ifndef SMTP_H
#define SMTP_H


#ifndef UCHAR_TYPEDEF_GUARD
#define UCHAR_TYPEDEF_GUARD
typedef unsigned char u_char;
#endif

/**
 * Analyse un paquet SMTP et affiche un résumé selon le niveau de verbosité 2 ou 3.
 * @param packet    Pointeur vers le début du payload TCP contenant les données SMTP.
 * @param length    Longeur du payload TCP disponible
 * @param verbosity Niveau de verbosité (2 ou 3) 
 * @param indent    Indentation en epsaces pour l'affichage
 * @return          Nombre d'octets consommés dans le payload TCP pour le protocole SMTP.
 */
int parse_smtp(const u_char *packet, int length, int verbosity, int indent);

/**
 * Résumé verbosité 1 pour SMTP (commande ou code de réponse).
 * 
 * @param packet              Pointeur vers le début du paquet complet.
 * @param caplen              Longueur capturée totale.
 * @param offset_tcp_payload  Offset du début du payload TCP (après TCP header).
 * @param resume              Buffer de sortie pour le résumé.
 * @return                    1 en succès, 0 en échec.
 */
int smtp_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

/* Commande SMTP utilisée pour la détection du contenu du mail */
#define SMTP_CMD_DATA       "DATA"

/* Ports SMTP */
#define SMTP_PORT_PLAIN 25   // SMTP non-chiffré
#define SMTP_PORT_SUBMISSION 587  // SMTP soumission (chiffré)
#define SMTP_PORT_SSL 465    // SMTPS (implicit TLS)


#endif /* SMTP_H */