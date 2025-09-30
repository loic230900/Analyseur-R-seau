CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
LDLIBS  := -lpcap

# cible principale
analyseur: analyseur.o
	$(CC) $^ -o $@ $(LDLIBS)

# règle de compilation des .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o analyseur
