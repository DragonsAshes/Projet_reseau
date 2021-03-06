#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "request.h"
#include "api.h"
#include "semantic.h"

int main(int argc, char* argv[])
{
	message* requete;
	char* response = NULL;
	char* validation_sem = NULL;
	message* res;

	while (1)
	{
		// on attend la reception d'une requete HTTP requete pointera vers une ressource allouée par librequest.
		if ((requete=getRequest(8080)) == NULL ) return -1;

		// Affichage de debug
		printf("#########################################\nDemande recue depuis le client %d\n",requete->clientId);
		printf("Client [%d] [%s:%d]\n",requete->clientId,inet_ntoa(requete->clientAddress->sin_addr),htons(requete->clientAddress->sin_port));
		printf("Contenu de la demande :\n%.*s\n\n",requete->len,requete->buf);

		//Vérification syntaxique
		if( parseur(requete->buf, requete->len) == 0 ) //Si le message n'a pas une syntaxe correcte
		{
			printf("La syntaxe du message est incorrecte");
			endWriteDirectClient(requete->clientId);
			freeRequest(requete);
			exit(EXIT_FAILURE);
		}

		//Vérification sémantique
		validation_sem = semantic_validation();

		//Création de la réponse en fonction du status code reçu
		response = createResponse(validation_sem);

		res = malloc(sizeof(message));
		res->buf=response;
		res->len=get_reponse_len();
		res->clientId = requete->clientId;


		sendReponse(res);

		char* co = get_connection();
		if (strcmp(co,"close") == 0){
			requestShutdownSocket(res->clientId);
		}

		//Libération de l'espace mémoire
		freeRequest(requete);
		free(res->buf);
		free(res);
		free(co);
		free(validation_sem);
		purgeTree(getRootTree());
		
	}
	return 1;
}
