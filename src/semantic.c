#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "semantic.h"
#include "api.h"

#define MAX_MAJOR_VERSION 1
#define MAX_MINOR_VERSION 1


char* headers[] = {"Transfer_Encoding_header", "Cookie_header", "Referer_header", "User_agent_header", "Accept_header", "Accept_Encoding_header",
	 "Content_Length_header", "Host_header", "Connection_header", "Accept_Charset_header"};
int headers_length = 10;


//Return 0 if each header is unique, else -1
int headers_unicity()
{
	_Token* tree;
	void *root = NULL;

	root = getRootTree();

	for(int i = 0; i < headers_length; i++)
	{
		tree = searchTree(root, headers[i]);
		if( tree != NULL )
		{
			printf("tree : %s\n", getElementTag(tree->node, NULL));
			if( tree->next != NULL )
			{
				printf("tree : %s\n", getElementTag(tree->next->node, NULL));
				purgeElement(&tree);
				return -1;
			}
		}
		purgeElement(&tree);
	}
	return 0;
}


int method_conformity()
{
	_Token* tree;
	void* root = getRootTree();
	char* method = NULL;
	char* body = NULL;

	tree = searchTree(root, "method");

	if(tree == NULL)
		return -1;

	if(tree->next != NULL)
		return -1;

	strcpy(method, getElementValue(tree->node, NULL));
	if( (strcmp(method, "GET") != 0) && (strcmp(method, "HEAD") != 0) && (strcmp(method, "POST") != 0) )
		return -1;

	if( strcmp(method, "GET") == 0 )
	{
		if( searchTree(root, "message_body") != NULL )
			return -1;
	}
	else if( strcmp(method, "HEAD") == 0 )
	{
		if( searchTree(root, "message_body") != NULL )
			return -1;
	}
	else if( strcmp(method, "POST") == 0 )
	{
		tree = searchTree(root, "message_body");
		if( tree != NULL )
		{
			strcpy(body, getElementValue(tree->node, NULL));
			tree = searchTree(root, "Content_Length_header");
			if( atoi(getElementValue(tree->node, NULL)) != strlen(body) )
				return -1;
		}
		else{
			tree = searchTree(root, "Content_Length_header");
			if( tree == NULL )
				return -1;
			if( atoi(getElementValue(tree->node, NULL)) != 0 )
				return -1;
		}

	}

	return 0;
}


int http_check()
{
	_Token* tree;
	void* root = getRootTree();
	char* version = NULL;
	float tmp;

	tree = searchTree(root, "HTTP_version");
	if( tree == NULL )
		return -1;
	if ( tree->next != NULL )
		return -1;

	version = getElementValue(tree->node, NULL);

	if( strcmp(version, "HTTP/1.0") == 0 )
	{
		return 0;
	}
	else if( strcmp(version, "HTTP/1.1") == 0 )
	{
		if( searchTree(root, "Host_header") == NULL )
			return -1;
		return 0;
	}

	tmp = atof(version+5);
	if( tmp > (float)(MAX_MAJOR_VERSION+0.1*MAX_MINOR_VERSION) )
		return -1;

	return 0;
}


char* semantic_validation()
{
	if( headers_unicity() == -1 ) //On regarde si chaque header est unique
		return "400 Bad Request";
	if( method_conformity() == -1 ) //On vérifie la conformité des méthodes et du champ message body
		return "501 Not Implemented";
	if( http_check() == -1 ) //vérification de la version HTTP, des headers alors obligatoires et du comportement par défaut pour la gestion de la connexion
		return "400 Bad Request";
	return "200 OK";
}


char* createResponse(char* statuscode)
{
	if( strcmp(statuscode, "200 OK") != 0 )
		return statuscode;

	return NULL;
}