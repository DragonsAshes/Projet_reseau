#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "request.h"   
#include "api.h"

int main(int argc, char* argv[])
{
	message* requete;
	char* reponse;

	while (1)
	{
		// on attend la reception d'une requete HTTP requete pointera vers une ressource allouée par librequest. 
		if ((requete=getRequest(8080)) == NULL ) return -1; 

		// Affichage de debug 
		printf("#########################################\nDemande recue depuis le client %d\n",requete->clientId); 
		printf("Client [%d] [%s:%d]\n",requete->clientId,inet_ntoa(requete->clientAddress->sin_addr),htons(requete->clientAddress->sin_port));
		printf("Contenu de la demande %.*s\n\n",requete->len,requete->buf);

		//Vérification syntaxique
		if( parseur(requete->buf, requete->len) == 0 ) //Si le message n'a pas une syntaxe correcte
		{
			printf("La syntaxe du message est incorrecte");
			endWriteDirectClient(requete->clientId);
			freeRequest(requete);
			exit(EXIT_FAILURE);
		}

		//Vérification sémantique

		writeDirectClient(requete->clientId, "CAZOU", 6);
		endWriteDirectClient(requete->clientId);

		freeRequest(requete);
		free(reponse);
	}
	return 1;
}