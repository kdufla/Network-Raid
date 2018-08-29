all: client server


client: client.c
	gcc -Wall -g client.c `pkg-config fuse --cflags --libs` -o hello -lpthread -lssl -lcrypto

server: server.c
	gcc server.c -g -o server -lpthread -lssl -lcrypto

clean:
	rm hello server

u:
	fusermount -u /home/vagrant/code/final/sa

m:
	./hello /home/vagrant/code/final/sa -o sync_read -f

mf:
	./hello -f /home/vagrant/code/final/sa

test:
	gcc test.c -o testexec
	strace ./testexec
	rm testexec