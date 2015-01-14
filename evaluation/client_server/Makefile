CC=gcc
# with debug 
#CFLAG=-g -Wall -DDEBUG=1
#without debug 
CFLAG=-g -Wall
LD= -L/usr/local/ssl/lib -lssl -lcrypto -ldl -lpthread

INCLUDES= -I/usr/local/ssl/include
CFLAGS= $(INCLUDES) $(CFLAG)
#CFLAGS= -DMONOLITH $(INCLUDES) $(CFLAG)
# (what is DMONOLITH doing?)

all:  wclient wserver mbox

wclient: wclient.o common.o 
	$(CC) $(CFLAGS) wclient.o  common.o  -o wclient $(LD)
wserver:  wserver.o common.o 
	$(CC) $(CFLAGS) wserver.o  common.o  -o wserver $(LD)
mbox: middlebox.o common.o 
	$(CC) $(CFLAGS) middlebox.o  common.o  -o mbox $(LD)

clean:	
	rm *.o wclient wserver mbox

