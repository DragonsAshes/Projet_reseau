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
	int access;
	size_t content_len;
	long response_len;
} Elements;

char* get_connection();

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

long get_reponse_len();

void DumpHex(const void* data, size_t size);

#endif
