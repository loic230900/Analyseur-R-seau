# Nom de l'exécutable
TARGET = analyseur

# Compilateur et flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE -g 


# Fichiers objets
OBJS = main.o capture.o hexdump.o filter.o \
	ethernet.o arp.o ipv4.o ipv6.o icmp.o icmpv6.o ndp.o udp.o dhcp.o tcp.o dns.o http.o smtp.o imap.o pop3.o textutils.o

# Règle par défaut
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) -lpcap

# Compilation des .c en .o
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Compilation des fichiers dans protocoles/
%.o: protocoles/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compilation des fichiers dans util/
%.o: util/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Cible de nettoyage
clean:
	rm -f $(OBJS) $(TARGET)
