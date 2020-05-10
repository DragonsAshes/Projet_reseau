#ifndef SEMANTIC_H
#define SEMANTIC_H

int headers_unicity();

char* semantic_validation();

int http_check();

int method_conformity();

int get_conformity();

char* createResponse(char* statuscode);

#endif