# Makefile for dragonshell

CC = gcc
CFLAGS = -Wall
TARGET = dragonshell
SRC = dragonshell.c
OBJ = dragonshell.o

# Main target: build the executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

# Compile only
compile:
	$(CC) $(CFLAGS) -c $(SRC)

# Clean object and executable files
clean:
	rm -f $(OBJ) $(TARGET)