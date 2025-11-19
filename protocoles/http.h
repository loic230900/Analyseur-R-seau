#ifndef HTTP_H
#define HTTP_H
#ifndef u_char
typedef unsigned char u_char;
#endif

#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h> 


/**
 * Analyse et affiche un message HTTP(Request ou Reponse).
 * @param packet    Pointeur vers le début du payload TCP contenant HTTP.
 * @param length    Longeur du payload TCP disponible.
 * @param verbosity Niveau de verbosité (2 ou 3).
 * @param indent    Indentation en espace pour l'affichage.
 * @return          Nombre d'octets consommés (headers + body si détecté),
 *                  ou 0 si ce n'est pas du HTTP ou erreur.
 */
int parse_http(const u_char *packet, int length, int verbosity, int indent);

/**
 * Résumé verbosité 1 pour HTTP (méthode+URI ou code status).
 * @param packet           Pointeur vers le début du paquet complet.
 * @param caplen           Longueur capturée totale.
 * @param offset_tcp_payload Offset du début du payload TCP (après TCP header).
 * @param resume           Buffer de sortie pour le résumé.
 * @return                 1 en succès, 0 en échec.
 */
int http_v1_summary(const u_char *packet, int caplen, int offset_tcp_payload, char *resume);

/*Methodes HTTP*/
#define HTTP_METHOD_GET     "GET"
#define HTTP_METHOD_POST    "POST"
#define HTTP_METHOD_PUT     "PUT"
#define HTTP_METHOD_DELETE  "DELETE"
#define HTTP_METHOD_HEAD    "HEAD"
#define HTTP_METHOD_OPTIONS "OPTIONS"

/*codes de status*/
#define HTTP_STATUS_OK              200
#define HTTP_STATUS_CREATED         201
#define HTTP_STATUS_MOVED           301
#define HTTP_STATUS_FOUND           302
#define HTTP_STATUS_NOT_MODIFIED    304
#define HTTP_STATUS_BAD_REQUEST     400
#define HTTP_STATUS_UNAUTHORIZED    401
#define HTTP_STATUS_FORBIDDEN       403
#define HTTP_STATUS_NOT_FOUND       404
#define HTTP_STATUS_SERVER_ERROR    500
#define HTTP_STATUS_NOT_IMPLEMENTED 501
#define HTTP_STATUS_BAD_GATEWAY     502


#endif /* HTTP_H */