PKG_CONFIG ?= pkg-config
CC=gcc

CFLAGS+=-c -Wall -O3 -DOSX  -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration 
LDFLAGS+=  -lm -lz -lpcap 
#LIBS=
CFLAGS +=-DDEBUG
CFLAGS +=-DTRANSPORT_LAYER_CAPTURE
SOURCES= util.c sha1.c   mac-parser.c 
OBJECTS=  $(SOURCES:.c=.o)

OBJECTS_START= oculus.o 
#OBJECTS_WRITE= write.o
EXECUTABLE=oculus

all:  $(EXECUTABLE)


$(EXECUTABLE):   $(OBJECTS) $(OBJECTS_START)
	$(CC)  $(OBJECTS)  $(OBJECTS_START) $(LDFLAGS)    -o $@

$(OBJECTS_START): oculus.c
	$(CC)  -D_GNU_SOURCE  $(CFLAGS) -o $@ $<

# -DCONFIG_LIBNL20   -I$(STAGING_DIR)/usr/include/mac80211 -I$(STAGING_DIR)/usr/include/libnl-tiny
#$(OBJECTS_WRITE): write.c
#	$(CC)  -D_GNU_SOURCE  $(CFLAGS) -o $@ $<


.o:	%.c 
	$(CC) $(CFLAGS)  -o $@ $<


clean:
	rm -rf *.o mac-darktest
