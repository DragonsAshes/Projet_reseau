#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include "semantic.h"
#include "api.h"

#define MAX_MAJOR_VERSION 1
#define MAX_MINOR_VERSION 1


char* headers[] = {"Transfer_Encoding_header", "Cookie_header", "Referer_header", "User_agent_header", "Accept_header", "Accept_Encoding_header",
	 "Content_Length_header", "Host_header", "Connection_header"};
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
	int len, body_len;
	char* content_length;
	char* tmp;

	tree = searchTree(root, "method");

	if(tree == NULL)
		return -1;

	if(tree->next != NULL)
		return -1;

	method = getElementValue(tree->node, &len);
	elements.method = malloc(sizeof(char) * (len+1));
	strncpy(elements.method, method, len);
	if( (strncmp(method, "GET", len) != 0) && (strncmp(method, "HEAD", len) != 0) && (strncmp(method, "POST", len) != 0) )
	{
		if( !strncmp(method, "PUT", len) || !strncmp(method, "DELETE", len) || !strncmp(method, "CONNECT", len) || !strncmp(method, "OPTIONS", len) || !strncmp(method, "TRACE", len))
			return -2;
		else
			return -1;
	}

	if( strncmp(method, "GET", len) == 0 )
	{
		tree = searchTree(root, "message_body");
		if( tree != NULL )
		{
			body = getElementValue(tree->node, &body_len);
			if( body_len != 0 )
				return -1;
		}
	}
	else if( strncmp(method, "HEAD", len) == 0 )
	{
		tree = searchTree(root, "message_body");
		if( tree != NULL )
		{
			body = getElementValue(tree->node, &body_len);
			if( body_len != 0 )
				return -1;
		}
	}
	else if( strncmp(method, "POST", len) == 0 )
	{
		tree = searchTree(root, "message_body");
		if( tree != NULL )
		{
			body = getElementValue(tree->node, &body_len);
			tree = searchTree(root, "Content_Length_header");
			if( tree == NULL )
				return -1;
			content_length = getElementValue(tree->node, &len);
			tmp = malloc(sizeof(char) * (len-strlen("Content-Length: ")));
			strncpy(tmp, content_length+strlen("Content-Length: "), len-strlen("Content-Length: "));

			if( atoi(tmp) != strlen(body))
			{
				free(tmp);
				return -1;
			}
			free(tmp);
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
			strncpy(elements.connection, etat+strlen("Connection: "), len-strlen("Connection: "));
			printf("Statut de la connexion :%s\n", elements.connection);
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
			strncpy(elements.connection, etat+strlen("Connection: "), len-strlen("Connection: "));
			printf("Statut de la connexion :%s\n", elements.connection);
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
	char* origin_form;

	tree = searchTree(root, "origin_form");
	if(tree == NULL)
		return -1;
	origin_form = getElementValue(tree->node, &len);

	tree = searchTree(root, "request_target");


	if(tree == NULL)
		return -1;

	if(tree->next != NULL)
		return -1;

	rtarget = getElementValue(tree->node, &len);

	//Vérification origin form
	if( strncmp(origin_form, rtarget, len) != 0 )
		return -1;

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



	tree = searchTree(root, "Host_header");
	if( tree != NULL )
	{
		int host_len;
		char* host = getElementValue(tree->node, &host_len);
		if(strncmp("www.", host+6, 4))
			strcat(rtarget_final, "www.");
		if(strncmp("127.0.0.1:8080", host+6, 14) == 0) //Redirection par défaut sur www.default.com
			strcat(rtarget_final, "default.com");
		else
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

	free(hexa);
	free(rtarget_final);
	free(rtarget_pe);

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

	FILE* f = fopen(elements.uri, "rb");
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
	free(cmd);
}


char* semantic_validation()
{
	elements.version = malloc(sizeof(char) * 10);
	elements.connection = malloc(sizeof(char) * 11);
	char* response = malloc(sizeof(char) * 100);
	int method_ret;
	if( headers_unicity() == -1 ) //On regarde si chaque header est unique
		strcpy(response, "400 Bad Request");
	method_ret = method_conformity();
	if( method_ret == -1 && !strcmp(response, "") ) //On vérifie la conformité des méthodes et du champ message body
		strcpy(response, "501 Not Implemented");
	if( method_ret == -2 && ! strcmp(response, "") )
		strcpy(response, "405 Not Allowed");
	if( http_check() == -1 && !strcmp(response, "") ) //vérification de la version HTTP, des headers alors obligatoires et du comportement par défaut pour la gestion de la connexion
		strcpy(response, "505 HTTP Version Not Supported");
	if( request_target_treatment() == -1 && !strcmp(response, "") )
		strcpy(response, "400 Bad Request");
	if(get_content() == -1 && !strcmp(response, "") )
		strcpy(response, "404 Not Found");
	if( !strcmp(response, "") )
		strcpy(response, "200 OK");
	printf("REPONSE : %s\n", response);
	return response;
}


char* createResponse(char* statuscode)
{
	time_t t = time(NULL);
	char buf[256];
	char* response = malloc(sizeof(char)* 2000);
	if( strcmp(statuscode, "200 OK") != 0 )
	{
		strcpy(response, elements.version);
		strcat(response, " ");
		strcat(response, statuscode);
		if( strncmp(statuscode, "405", 3) == 0 )
		{
			strcat(response, "\r\n");
			strcat(response, "Allow: GET, POST, HEAD");
		}
		strcat(response, "\r\n\r\n");
		strcat(response, "<html>");
		strcat(response, "Error ");
		strcat(response, statuscode);
		strcat(response, "</html>");
	}
	else
	{
		strcpy(response, elements.version);
		strcat(response, " ");
		strcat(response, statuscode);
		strcat(response, "\r\n");
		strcat(response, "Date: ");
		strftime(buf, sizeof(buf), "%A %d %B %Y - %X.", localtime(&t));
		strcat(response, buf);
		strcat(response, "\r\n");
		strcat(response, "Connection: ");
		strcat(response, elements.connection);
		strcat(response, "\r\n");
		strcat(response, "Content-type: ");
		strcat(response, elements.mime);
		strcat(response, "\r\n");
		strcat(response, "Content-Length: ");
		char* len;
		sprintf(len, "%ld", strlen(elements.content));
		strcat(response, len);
		strcat(response, "\r\n\r\n");
		if(strcmp(elements.method, "HEAD") != 0)
		{
			strcat(response, elements.content);
			strcat(response, "\r\n");
		}
	}
	free(elements.method);
	free(elements.version);
	free(elements.uri);
	free(elements.mime);
	free(elements.content);

	return response;
}