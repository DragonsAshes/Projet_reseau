#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
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


int isHex(char c)
{
	return (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102); 
}

int request_target_treatment()
{
	_Token* tree;
	char tmp;
	int len;
	int j = 0;
	void* root = getRootTree();
	char* rtarget;
	char* hexa = malloc(sizeof(char)*3);
	char* rtarget_pe, *rtarget_dsr;

	tree = searchTree(root, "request_target");

	if(tree == NULL)
		return -1;

	if(tree->next != NULL)
		return -1;

	rtarget = getElementValue(tree->node, &len);

	printf("target initial : %d %s\n",len, rtarget);

	rtarget_pe = malloc(sizeof(char)*len+1);

	for(int i = 0; i < len; i++)
	{
		if( i < len-3 && rtarget[i] == '%' && isHex(rtarget[i+1]) && isHex(rtarget[i+2]) )
		{
			hexa[0] = rtarget[i+1];
			hexa[1] = rtarget[i+2];
			tmp = (int)strtol(hexa, NULL, 16);
			rtarget_pe[j] = tmp;
			i += 2;
		}
		else
		{
			rtarget_pe[j] = rtarget[i];
		}
		j++;
	}
	rtarget_pe[j] = '\0';
	len = strlen(rtarget_pe);
	j = 0;

	rtarget_dsr = malloc(sizeof(char)* len+1);

	for(int i = 0; i < len; i++)
	{
		if( (i < len-3 && rtarget_pe[i] == '.' && rtarget_pe[i+1] == '.' && rtarget_pe[i+2] == '/')
			|| (i < len-2 && rtarget_pe[i] == '.' && rtarget_pe[i+1] == '/'))
		{
			if( rtarget_pe[i+1] == '.' )
				i += 2;
			else
				i++;
		}
		else if( (i< len-3 && rtarget_pe[i] == '/' && rtarget_pe[i+1] == '.' && rtarget_pe[i+2] == '/')
			|| (i < len-3 && rtarget_pe[i] == '/' && rtarget_pe[i+1] == '.' && rtarget_pe[i+2] != '.') )
		{
			if( i < len-3 && rtarget_pe[i+2] == '/' )
				i++;
			else
				rtarget_pe[i++] = '/';
		}
		else if( (i < len-4 && strncmp(rtarget_pe+i, "/../", 4) == 0) || (i < len-3 && strncmp(rtarget_pe+i, "/..", 3) == 0))
		{
			if( i < len-4 && rtarget_pe[i+3] == '/')
				i += 2;
			else
			{
				rtarget_pe[i+2] = '/';
				i++;
			}
			while( rtarget_dsr[j] != '/' && j > 0) j--;
		}
		else if( strcmp(rtarget_pe, ".") == 0 )
			i++;
		else if( strcmp(rtarget_pe, "..") == 0 )
			i += 2;

		else
			rtarget_dsr[j++] = rtarget_pe[i];


	}

	rtarget_dsr[j] = '\0';


	char* rtarget_final = malloc( sizeof(char) * (strlen(rtarget_dsr) + strlen("index.html") + 5));

	strcpy(rtarget_final, "www.");

	tree = searchTree(root, "Host_header");
	if( tree != NULL )
	{
		int host_len;
		char* host = getElementValue(tree->node, &host_len);
		strncat(rtarget_final, host+6, host_len-strlen("Host: "));
	}

	strcat(rtarget_final, rtarget_dsr);


	int isdir = 0;
	struct stat statbuf;
	if( stat(rtarget_final, &statbuf) != -1 )
		isdir = S_ISDIR(statbuf.st_mode);

	if( isdir || rtarget_final[strlen(rtarget_final) -1] == '/' )
	{
		if( rtarget_final[strlen(rtarget_final) -1] != '/' )
			strcat(rtarget_final, "/");
		strcat(rtarget_final, "index.html");
	}
	printf("target = %s\n", rtarget_final);
	elements.uri = malloc(sizeof(char) * strlen(rtarget_final));
	strcpy(elements.uri, rtarget_final);
	return 0;
}



int get_content()
{
	if( access(elements.uri, R_OK) == -1 )
	{
		printf("ERREUR ACCESS\n");
		return -1;
	}

	get_Mime();

	if( elements.mime == NULL )
	{
		printf("ERREUR MIME\n");
		return -1;
	}

	FILE* f = fopen(elements.uri, "r");
	if( f == NULL )
	{
		printf("ERREUR FOPEN\n");
		return -1;
	}

	fseek(f, 0, SEEK_END);

	int len = ftell(f);

	fseek(f, 0, SEEK_SET);

	elements.content = malloc(sizeof(char) * len);
	fread( elements.content, 1, len, f);

	printf("content : \n%s\n", elements.content);

	fclose(f);

	return 0;
}

void get_Mime()
{
	char* cmd = malloc(sizeof(char)* (strlen("file -i ") + strlen(elements.uri)) );
	strcpy(cmd, "file -i ");
	strcat(cmd, elements.uri);
	printf("check : %s\n", elements.uri);

	FILE* f = popen(cmd, "r");

	char info[1024];
	if( fgets(info, sizeof(info)-1, f) == NULL)
	{
		printf("ERREUR FGETS\n");
		pclose(f);
		return;
	}

	printf("info : %s\n", info);

	char* tmp;
	tmp = strtok(info, " :;");

	if(tmp != NULL)
	{
		tmp = strtok( NULL, ":; ");
		if(tmp != NULL)
		{
			elements.mime = malloc(sizeof(char) * strlen(tmp));
			strcpy(elements.mime, tmp);
		}
	}

	pclose(f);

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
	request_target_treatment();
	get_content();
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