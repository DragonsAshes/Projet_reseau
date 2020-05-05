#include "semantic.h"
#include "api.h"

char headers[] = {"Transfer_Encoding_header", "Cookie_header", "Referer_header", "User_agent_header", "Accept_header", "Accept_Encoding_header",
	 "Content_Length_header", "Host_header", "Connection_header"};
int headers_length = 9;


//Return 0 if each header is unique, else -1
int headers_unicity()
{
	_Token* tree;

	for(int i = 0; i < headers_length; i++)
	{
		tree = searchTree(NULL, headers[i]);
		if( tree != NULL )
		{
			if( tree->next != NULL)
			{
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