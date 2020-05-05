
all : main

main : librequest.so libparser.so main.o 
	gcc -g -o main main.o -L. -lrequest -lparser

main.o: main.c
	gcc -fPIC -g -I./api -c $< 

clean : 
	rm -rf *.o 

