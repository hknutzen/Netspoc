/* append-commitlog						*/
/* This should be installed setuid and setgid.			*/

#include <stdio.h>

char commitlog[] = "/home/diamonds/netspoc/commitlog";

int main( int argc, char *argv[]) 
{
    /* Append mode */
    FILE *out = fopen( commitlog, "a" );
    if(out == NULL) {
	perror("");
	exit(1);
    }

    while(1) {
	char ch;
	ch = fgetc(stdin);
	if(ch == EOF) {
	    break;
	}
	fputc(ch, out);
    }
} 

