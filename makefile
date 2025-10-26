# Nom de l'exécutable
TARGET = analyseur

# Compilateur et flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE -g 


# Fichiers objets
OBJS = main.o capture.o hexdump.o \
       protocoles/ethernet.o protocoles/ipv4.o protocoles/ipv6.o \
       protocoles/udp.o protocoles/dhcp.o

# Règle par défaut
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) -lpcap

# Compilation des .c en .o
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Cible de nettoyage
clean:
	rm -f $(OBJS) $(TARGET)
