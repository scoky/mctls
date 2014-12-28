CC=gcc
CFLAGS=-g  -Wall 
LD= -lssl -lcrypto


all:  wclient wserver

wclient: wclient.o common.o 
	$(CC) wclient.o  common.o  -o wclient $(LD)

wserver:  wserver.o common.o 
	$(CC) wserver.o  common.o -o wserver $(LD)


clean:	
	rm *.o wclient wserver 

