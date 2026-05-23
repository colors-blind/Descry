#   Building Open Source Network Security Tools
#   Descry Makefile - Network Instrusion Detection Technique sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .

CC		= gcc -g
CFLAGS		= -O2 -Wall
#LDFLAGS        = -L/path/to/libpcap/and/libnet/library/if/needed
OBJECTS         = descry.o
#INCS           = -I/path/to/libpcap/and/libnet/headers/if/needed
LIBS		= -lpcap -lnet

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: descry

descry: $(OBJECTS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ *core* descry

# EOF
