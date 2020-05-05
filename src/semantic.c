#include <stdio.h>
#include <stdlib.h>
#include "semantic.h"
#include "api.h"


char* headers[] = {"Transfer_Encoding_header", "Cookie_header", "Referer_header", "User_agent_header", "Accept_header", "Accept_Encoding_header",
	 "Content_Length_header", "Host_header", "Connection_header"};
int headers_length = 9;


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


int semantic_validation()
{
	return headers_unicity();
}