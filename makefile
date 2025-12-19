# Nom de l'exécutable
TARGET       = analyseur

# Dossiers
SRC_DIR      = src
PROTO_DIR    = protocoles
INCLUDE_DIR  = include
OBJ_DIR      = obj

# Compilateur et flags
CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -Wconversion -std=c99 -D_DEFAULT_SOURCE -O2 -g \
		  -I$(INCLUDE_DIR) -I$(INCLUDE_DIR)/util -I$(PROTO_DIR)/include

# Sources
SRC_FILES   = $(SRC_DIR)/main.c $(SRC_DIR)/capture.c $(SRC_DIR)/detection.c \
              $(SRC_DIR)/dispatch.c $(SRC_DIR)/hexdump.c $(SRC_DIR)/filter.c \
              $(SRC_DIR)/util/textutils.c
PROTO_FILES = $(wildcard $(PROTO_DIR)/*.c)

# Objets
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES)) \
       $(patsubst $(PROTO_DIR)/%.c,$(OBJ_DIR)/protocoles/%.o,$(PROTO_FILES))

# Règle par défaut
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) -lpcap

# Compilation des sources hors protocoles
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Compilation des fichiers protocoles
$(OBJ_DIR)/protocoles/%.o: $(PROTO_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Cible de nettoyage
.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(TARGET)
