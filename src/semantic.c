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
int headers_length = 9;

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
			if( tree->next != NULL )
			{
				purgeElement(&tree);
				return -1;
			}
		}
		purgeElement(&tree);
	}
	return 0;
}

//Retourne 0 si la méthode est conforme et que le message body l'est aussi
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
	{
		purgeElement(&tree);
		return -1;
	}

	method = getElementValue(tree->node, &len);
	elements.method = calloc(len+1, 1);
	strncpy(elements.method, method, len);
	if( (strncmp(method, "GET", len) != 0) && (strncmp(method, "HEAD", len) != 0) && (strncmp(method, "POST", len) != 0) )
	{
		if( !strncmp(method, "PUT", len) || !strncmp(method, "DELETE", len) || !strncmp(method, "CONNECT", len) || !strncmp(method, "OPTIONS", len) || !strncmp(method, "TRACE", len))
		{
			purgeElement(&tree);
			return -2;
		}
		else
		{
			purgeElement(&tree);
			return -1;
		}
	}
	purgeElement(&tree);
	if( strncmp(method, "GET", len) == 0 )
	{
		tree = searchTree(root, "message_body");
		if( tree != NULL )
		{
			body = getElementValue(tree->node, &body_len);
			if( body_len != 0 )
			{
				purgeElement(&tree);
				return -1;
			}
		}
		purgeElement(&tree);
	}
	else if( strncmp(method, "HEAD", len) == 0 )
	{
		tree = searchTree(root, "message_body");
		if( tree != NULL )
		{
			body = getElementValue(tree->node, &body_len);
			if( body_len != 0 )
			{
				purgeElement(&tree);
				return -1;
			}
		}
		purgeElement(&tree);
	}
	else if( strncmp(method, "POST", len) == 0 )
	{
		tree = searchTree(root, "message_body");
		if( tree != NULL )
		{
			body = getElementValue(tree->node, &body_len);
			purgeElement(&tree);
			tree = searchTree(root, "Content_Length_header");
			if( tree == NULL )
				return -1;
			content_length = getElementValue(tree->node, &len);
			tmp = calloc(len-strlen("Content-Length: "), 1);
			strncpy(tmp, content_length+strlen("Content-Length: "), len-strlen("Content-Length: "));

			if( atoi(tmp) != strlen(body))
			{
				free(tmp);
				purgeElement(&tree);
				return -1;
			}
			purgeElement(&tree);
			free(tmp);
		}
		else{
			return -1;
		}

	}
	return 0;
}

//Retourne 0 si la version d'http est supportée par le serveur
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
	{
		purgeElement(&tree);
		return -1;
	}

	version = getElementValue(tree->node, &len);
	elements.version = calloc(len+1, 1);
	strncpy(elements.version,version, len);
	purgeElement(&tree);
	if( strncmp(version, "HTTP/1.0", len) == 0 )
	{
		//On récupère l'état de la connexion
		tree = searchTree(root, "Connection_header");
		if( tree != NULL )
		{
			etat = getElementValue(tree->node, &len);
			elements.connection = calloc(len +1, 1);
			strncpy(elements.connection, etat+strlen("Connection: "), len-strlen("Connection: "));
			printf("Statut de la connexion: %s\n", elements.connection);
		}
		else
		{
			elements.connection = calloc(6, 1);
			strcpy(elements.connection, "close");
		}
		purgeElement(&tree);
		return 0;
	}
	else if( strncmp(version, "HTTP/1.1", len) == 0 )
	{
		if( searchTree(root, "Host_header") == NULL )
			return -1;
		purgeElement(&tree);
		tree = searchTree(root, "Connection_header");
		if( tree != NULL )
		{
			etat = getElementValue(tree->node, &len);
			elements.connection = calloc(len+1, 1);
			strncpy(elements.connection, etat+strlen("Connection: "), len-strlen("Connection: "));
			printf("Statut de la connexion: %s\n", elements.connection);
		}
		else
		{
			elements.connection = calloc(11, 1);
			strcpy(elements.connection, "keep_alive");
		}
		purgeElement(&tree);
		return 0;
	}

	tmp = atof(version+5);
	if( tmp > (float)(MAX_MAJOR_VERSION+0.1*MAX_MINOR_VERSION) )
		return -1;

	purgeElement(&tree);
	return 0;
}

//Fonction permettant de détermine si un cractère est un caractère hexadecimal
int isHex(char c)
{
	return (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
}

/*Fonction permettant de vérifier le type origin-form, de réaliser le percent encoding et le dot segment removal
Cette fonction forme aussi le path absolu vers le fichier en prenant en compte l'existence ou non du host header*/
int request_target_treatment()
{
	_Token* tree;
	char tmp;
	int len;
	int j = 0;
	void* root = getRootTree();
	char* rtarget;
	char* hexa = calloc(3, 1);
	char* rtarget_pe, *rtarget_dsr;
	char* origin_form;

	tree = searchTree(root, "origin_form");
	if(tree == NULL)
		return -1;
	origin_form = getElementValue(tree->node, &len);

	purgeElement(&tree);
	tree = searchTree(root, "request_target");


	if(tree == NULL)
		return -1;

	if(tree->next != NULL)
	{
		purgeElement(&tree);
		return -1;
	}

	rtarget = getElementValue(tree->node, &len);

	//Vérification origin form
	if( strncmp(origin_form, rtarget, len) != 0 )
	{
		purgeElement(&tree);
		return -1;
	}

	rtarget_pe = calloc(len+1, 1);

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

	rtarget_dsr = calloc(len+1, 1);

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


	char* rtarget_final = calloc(strlen(rtarget_dsr) + strlen("index.html") + 32, 1);


	purgeElement(&tree);
	tree = searchTree(root, "Host_header");
	if( tree != NULL )
	{
		int host_len;
		char* host = getElementValue(tree->node, &host_len);
		if(strncmp("www.", host+6, 4))
			strcat(rtarget_final, "www.");
		if(strncmp("127.0.0.1:8080", host+6, 14) == 0) //Redirection par défaut sur www.default.com
			strcat(rtarget_final, "toto.com");
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
	elements.uri = calloc(strlen(rtarget_final)+1, 1);
	strcpy(elements.uri, rtarget_final);

	purgeElement(&tree);
	free(hexa);
	free(rtarget_final);
	free(rtarget_pe);
	free(rtarget_dsr);

	return 0;
}


//Fonction permettant de récupérer le contenu d'un fichier
int get_content()
{
	if( access(elements.uri, R_OK) == -1 )
	{
		elements.access = 0;
		printf("ERREUR ACCESS\n");
		return -1;
	}

	get_Mime();

	if( elements.mime == NULL )
	{
		elements.access = 0;
		printf("ERREUR MIME\n");
		return -1;
	}

	FILE* f = fopen(elements.uri, "a+");
	if( f == NULL )
	{
		elements.access = 0;
		printf("ERREUR FOPEN\n");
		return -1;
	}

	fseek(f, 0, SEEK_END);

	size_t len = ftell(f);

	fseek(f, 0, SEEK_SET);
	printf("taille %ld\n", len);
	elements.content = calloc(len + 1, 1);
	elements.content_len = len;

	fread( elements.content, 1, len, f);
	printf("%s\n", elements.content);

	fclose(f);

	return 0;
}

//Fonction permettant de déterminer le type mime d'un fichier
void get_Mime()
{
	char* cmd = calloc(strlen("file -i ") + strlen(elements.uri) +1, 1);
	strcpy(cmd, "file -i ");
	strcat(cmd, elements.uri);
	printf("check : %s\n", cmd);

	FILE* f = popen(cmd, "r");

	char info[1024];
	if( fgets(info, sizeof(info)-1, f) == NULL)
	{
		elements.access = 0;
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
			elements.mime = calloc(strlen(tmp) + 1, 1);
			strcpy(elements.mime, tmp);
		}
	}

	free(cmd);
	pclose(f);
}


//Cette fonction réalise la vérification sémantique et retourne le statuscode approprié
char* semantic_validation()
{
	char* response = calloc(100, 1);
	int method_ret;
	elements.access = 1;
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

//Cette fonction permet de créer la réponse en fonction du statuscode et des éléments récupérer dans la structure elements
char* createResponse(char* statuscode)
{
	time_t t = time(NULL);
	char buf[256];
	char* response;
	char* len;
	int size = 0;
	if( strcmp(statuscode, "200 OK") != 0 )
	{
		response = calloc(512, 1);
		strcpy(response, elements.version);
		strcat(response, " ");
		strcat(response, statuscode);
		if( strncmp(statuscode, "405", 3) == 0 )
		{
			strcat(response, "\r\n");
			strcat(response, "Allow: GET, POST, HEAD");
		}
		strcat(response, "\r\n");
		strcat(response, "Content-Length: ");
		len = calloc(10, 1);
		size = strlen(statuscode);
		size += 16;
		sprintf(len, "%d", size);
		strcat(response, len);
		strcat(response, "\r\n\r\n");
		strcat(response, "<html>");
		strcat(response, "Error ");
		strcat(response, statuscode);
		strcat(response, "</html>");
	}
	else
	{
		response = calloc(512 + strlen(elements.content), 1);
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
		len = calloc(10, 1);
		size = strlen(elements.content);
		sprintf(len, "%d", size);
		strcat(response, len);
		strcat(response, "\r\n\r\n");
		if(strcmp(elements.method, "HEAD") != 0)
		{
			strncat(response, elements.content, elements.content_len);
			strcat(response, "\r\n");
		}

	}
	free(len);
	free(elements.method);
	free(elements.version);
	free(elements.uri);
	if(elements.access == 1)
	{
		free(elements.content);
		free(elements.mime);
	}
	printf("\n\n%s\n\n", response);
	return response;
}

char* get_connection()
{
	return elements.connection;
}
