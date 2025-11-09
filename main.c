#include <pcap.h>          
#include <stdio.h>         
#include <stdlib.h>
#include <unistd.h>                
#include <string.h>
#include "capture.h"
#include "protocoles/dns.h"
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

    // Traduction minimale d'alias, déléguée au module DNS
    // On accepte 'dns' ou 'alldns' comme synonymes.
    if (filter_exp) {
        if (strcmp(filter_exp, "dns") == 0 || strcmp(filter_exp, "alldns") == 0) {
            filter_exp = (char*)dns_bpf_all();
        }
    }

    //application du filtre BPF si fourni (après éventuelle traduction)
    if (filter_exp) {
        struct bpf_program fp;
        bpf_u_int32 net = 0, mask = 0; 
        if(interface){
            //obtention du masque et de l'adresse reseau
            if(pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Erreur lors de la récupération du réseau et du masque pour l'interface %s: %s\n", interface, errbuf);
                net = 0;
                mask = 0;
            }
        }
        if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Erreur lors de la compilation du filtre %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_close(handle);
            return 2;
        }
        if(pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Erreur lors de l'application du filtre %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return 2;
        }
    
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