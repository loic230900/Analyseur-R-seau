#include <pcap.h>          
#include <stdio.h>         
#include <stdlib.h>
#include <unistd.h>                
#include <string.h>
#include "capture.h"
#include "protocoles/dns.h"
#include "filter.h"
#include <bits/getopt_core.h>


int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *filename = NULL;
    char *filter_exp = NULL;
    int opt;
    int verbosity = 3;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    //parsing options
    while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;   // nom de l'interface pour capture live
                break;
            case 'o':
                filename = optarg;    // nom du fichier .pcap pour capture offline
                break;
            case 'f':
                filter_exp = optarg;  // expression de filtre BPF
                break;
            case 'v':
                verbosity = atoi(optarg); 
                if(verbosity < 1 || verbosity > 3){
                    fprintf(stderr, "Niveau de verbosité invalide(doit être entre 1 et 3).\n");
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "Usage: %s [-i interface | -o fichier] [-f filtre] [-v niveau_verbosité]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    //verification des arguments
    if ((interface && filename) || (!interface && !filename)) {
        fprintf(stderr, "Erreur : Vous devez fournir soit une interface (-i) soit un fichier de sortie (-o), mais pas les deux.\n");
        return 1;
    }

    //ouverture de la capture
    if(interface) {
        //mode live
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if(handle == NULL) {
            fprintf(stderr, "Erreur lors de l'ouverture de l'interface %s: %s\n", interface, errbuf);
            return 2;
        }
    } else {
        //mode offline
        handle = pcap_open_offline(filename, errbuf);
        if(handle == NULL) {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier %s: %s\n", filename, errbuf);
            return 2;
        }
    }

    // Application du filtre
    if (filter_exp) {
        char applied[256];
        int fres = filter_apply(handle, interface, filter_exp, applied, sizeof(applied));
        if (fres != FILTER_OK) {
            pcap_close(handle);
            return 2;
        }
        fprintf(stderr, "Filtre BPF appliqué: %s\n", applied);
    }

    //boucle de capture des paquets
    capture_args_t args;
    args.verbosity = verbosity;

    if(pcap_loop(handle,-1, packet_handler, (u_char * )&args) == -1) {
        fprintf(stderr, "Erreur lors de la capture des paquets: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }
    pcap_close(handle);
    
    return 0;

}