
all : main

main : librequest.so libparser.so main.o semantic.o
	gcc -g -o main main.o semantic.o -L. -lrequest -lparser

main.o: main.c
	gcc -fPIC -g -I./api -c $< 

semantic.o : semantic.c
	gcc -fPIC -g -I./api -c $< 

clean : 
	rm -rf *.o 

