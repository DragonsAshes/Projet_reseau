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

Elements elements;


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
	int len;

	tree = searchTree(root, "method");

	if(tree == NULL)
		return -1;

	if(tree->next != NULL)
		return -1;

	method = getElementValue(tree->node, &len);
	if( (strncmp(method, "GET", len) != 0) && (strncmp(method, "HEAD", len) != 0) && (strncmp(method, "POST", len) != 0) )
		return -1;

	if( strncmp(method, "GET", len) == 0 )
	{
		if( searchTree(root, "message_body") != NULL )
			return -1;
	}
	else if( strncmp(method, "HEAD", len) == 0 )
	{
		if( searchTree(root, "message_body") != NULL )
			return -1;
	}
	else if( strncmp(method, "POST", len) == 0 )
	{
		tree = searchTree(root, "message_body");
		if( tree != NULL )
		{
			body = getElementValue(tree->node, NULL);
			tree = searchTree(root, "Content_Length_header");
			if( tree == NULL )
				return -1;
			printf("LBODY : %s\n", getElementValue(tree->node, NULL));
			//Utiliser strtok() pour récupérer la valeur

			if( atoi(getElementValue(tree->node, NULL)) != strlen(body) )
				return -1;
		}
		else{
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
	char* etat = NULL;
	char* etat2 = NULL;
	float tmp;
	int len;
	char* sep = ": \r\n";

	tree = searchTree(root, "HTTP_version");
	if( tree == NULL )
		return -1;
	if ( tree->next != NULL )
		return -1;

	version = getElementValue(tree->node, &len);
	printf("VERSION : %s", version);
	strncpy(elements.version,version, len);

	if( strncmp(version, "HTTP/1.0", len) == 0 )
	{
		//On récupère l'état de la connexion
		tree = searchTree(root, "Connection_header");
		if( tree != NULL )
		{
			etat = getElementValue(tree->node, &len);
			etat2 = strtok(etat, sep);
			printf("Statut de la connexion :%s\n", etat2);
			//Si ca vaut close -> elements.connection = close, idem pour keep-alive
		}
		else
			strcpy(elements.connection, "close");
		return 0;
	}
	else if( strncmp(version, "HTTP/1.1", len) == 0 )
	{
		if( searchTree(root, "Host_header") == NULL )
			return -1;
		tree = searchTree(root, "Connection_header");
		if( tree != NULL )
		{
			etat = getElementValue(tree->node, &len);
			etat2 = strtok(etat, sep);
			printf("Statut de la connexion :%s\n", etat2);
			//Si ca vaut close -> elements.connection = close, idem pour keep-alive
		}
		else
			strcpy(elements.connection, "keep_alive");
		
		return 0;
	}

	tmp = atof(version+5);
	if( tmp > (float)(MAX_MAJOR_VERSION+0.1*MAX_MINOR_VERSION) )
		return -1;

	return 0;
}


char* semantic_validation()
{
	elements.version = malloc(sizeof(char) * 10);
	elements.connection = malloc(sizeof(char) * 11);
	char* response = malloc(sizeof(char) * 100);
	if( headers_unicity() == -1 ) //On regarde si chaque header est unique
		strcpy(response, "400 Bad Request");
	if( method_conformity() == -1 && response == NULL ) //On vérifie la conformité des méthodes et du champ message body
		strcpy(response, "501 Not Implemented");
	if( http_check() == -1 && response == NULL ) //vérification de la version HTTP, des headers alors obligatoires et du comportement par défaut pour la gestion de la connexion
		strcpy(response, "400 Bad Request");
	if( !strcmp(response, "") )
	{
		strcpy(response, "200 OK");
	}
	printf("REPONSE : %s\n", response);
	return response;
}


char* createResponse(char* statuscode)
{
	char* response = malloc(sizeof(char)* 2000);
	if( strcmp(statuscode, "200 OK") != 0 )
	{
		strcpy(response, elements.version);
		strcat(response, " ");
		strcat(response, statuscode);
		strcat(response, "\r\n\r\n");
		strcat(response, "<html>");
		strcat(response, "Error ");
		strcat(response, statuscode);
		strcat(response, "</html>");
		return response;
	}
	else
	{
		strcpy(response, elements.version);
		strcat(response, " ");
		strcat(response, statuscode);
		strcat(response, "\r\n");
	}
}