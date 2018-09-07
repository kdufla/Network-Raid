all: client server


client: client.c
	gcc -Wall -g client.c parse.c logger.c raid1.c `pkg-config fuse --cflags --libs` -o client -lpthread -lssl -lcrypto

server: server.c
	gcc server.c -g -o server -lpthread -lssl -lcrypto

clean:
	rm client server

u:
	fusermount -u /home/vagrant/code/final/sa

md:
	gdb --args ./client /home/vagrant/code/final/sa -o sync_read -f

m:
	./client /home/vagrant/code/final/CONFIG

mf:
	./hello -f /home/vagrant/code/final/sa

test:
	gcc test.c -o testexec
	strace ./testexec
	rm testexec
