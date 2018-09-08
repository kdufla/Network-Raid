all: client server


client: client.c
	gcc -Wall -g client.c parse.c logger.c raid1.c raid5.c cache.c `pkg-config fuse --cflags --libs` -o client -lpthread -lssl -lcrypto

server: server.c
	gcc server.c -g -o server -lpthread -lssl -lcrypto

clean:
	rm client server

u:
	fusermount -uz /home/vagrant/code/final/sa

md:
	gdb --args ./client /home/vagrant/code/final/CONFIG

m:
	./client /home/vagrant/code/final/CONFIG

mf:
	./hello -f /home/vagrant/code/final/sa

test:
	gcc test.c -o testexec
	strace ./testexec
	rm testexec
