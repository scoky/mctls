CC=gcc
#CFLAG=-g -Wall -static
# (static give some warnings)
CFLAG=-g -Wall
LD= -L/home/scoky/Downloads/spp-test-build/lib -lssl -lcrypto -ldl -lpthread
#LD= -lssl -lcrypto
# (compile with system-wise libraries)

INCLUDES= -I/home/scoky/Downloads/spp-test-build/include
CFLAGS= $(INCLUDES) $(CFLAG)
#CFLAGS= -DMONOLITH $(INCLUDES) $(CFLAG)
# (what is DMONOLITH doing?)

all:  wclient wserver mbox

wclient: wclient.o common.o 
	$(CC) $(INCLUDES) $(CFLAG) wclient.o  common.o  -o wclient $(LD)
wserver:  wserver.o common.o 
	#$(CC) wserver.o  common.o -o wserver $(LD)
	$(CC) $(INCLUDES) $(CFLAG) wserver.o  common.o  -o wserver $(LD)
mbox: middlebox.o common.o 
	$(CC) $(INCLUDES) $(CFLAG) middlebox.o  common.o  -o mbox $(LD)
clean:	
	rm *.o wclient wserver mbox

