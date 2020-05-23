#ifndef SEMANTIC_H
#define SEMANTIC_H

typedef struct elements
{
	char* method;
	char* version;
	char* connection;
	char* uri;
	char* mime;
	char* content;
} Elements;


int headers_unicity();

char* semantic_validation();

int http_check();

int method_conformity();

int get_conformity();

int isHex(char c);

int request_target_treatment();

int get_content();

char* createResponse(char* statuscode);

void get_Mime();

#endif