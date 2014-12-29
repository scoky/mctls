CC=gcc
#CFLAG=-g -Wall -static
# (static give some warnings)
CFLAG=-g -Wall
LD= -L/usr/local/ssl/lib -lssl -lcrypto -ldl
#LD= -lssl -lcrypto
# (compile with system-wise libraries)

INCLUDES= -I/usr/local/ssl/include
CFLAGS= $(INCLUDES) $(CFLAG)
#CFLAGS= -DMONOLITH $(INCLUDES) $(CFLAG)
# (what is DMONOLITH doing?)

all:  wclient wserver

wclient: wclient.o common.o 
	$(CC) $(INCLUDES) $(CFLAG) wclient.o  common.o  -o wclient $(LD)
wserver:  wserver.o common.o 
	#$(CC) wserver.o  common.o -o wserver $(LD)
	$(CC) $(INCLUDES) $(CFLAG) wserver.o  common.o  -o wserver $(LD)

clean:	
	rm *.o wclient wserver 

