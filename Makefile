CC=gcc
CFLAGS=  -fno-pie -O1 -Wall -g -lseccomp -ludev
LDFLAGS=
SOURCES= usbnonce.c 

EXECUTABLE=usbnonce

all: $(SOURCES) 
		$(CC) $(CFLAGS) -o $(EXECUTABLE) $(SOURCES)
