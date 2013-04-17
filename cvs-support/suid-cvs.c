/* Wrapper script for cvs					*/
/* This should be installed setuid and setgid.			*/
/* 	$Id$	*/

#ifndef lint
static char vcid[] = "$Id$";
#endif /* lint */

#include <stdio.h>

char program[] = "/usr/local/bin/cvs";

void usage( void ) {
    fprintf(stderr, "Usage: suid-cvs server\n");
    exit(1);
}

int main( int argc, char *argv[]) 
{
    if(argc != 2) {
	usage ();
    }
    if(strcmp(argv[1], "server") != 0) {
	usage ();
    }
    char *env[] = { NULL };

    /* Call with checked argument vector and empty environment.	*/
    return execve(program, argv, env); 
} 

