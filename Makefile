all: client server


client: client.c
	gcc -Wall -g client.c parse.c logger.c raid1.c raid5.c `pkg-config fuse --cflags --libs` -o client -lpthread -lssl -lcrypto

server: server.c
	gcc server.c -g -o server -lpthread -lssl -lcrypto

clean:
	rm client server

u:
	fusermount -uz /home/ggvel/Documents/Network-Raid/sa

md:
	gdb --args ./client /home/ggvel/Documents/Network-Raid/CONFIG

m:
	./client /home/ggvel/Documents/Network-Raid/CONFIG

mf:
	./hello -f /home/ggvel/Documents/Network-Raid/sa

test:
	gcc test.c -o testexec
	strace ./testexec
	rm testexec
