/* Wrapper script for newpolicy.pl				*/
/* This should be installed setuid and setgid.			*/
/* 	$Id$	*/

#ifndef lint
static char vcid[] = "$Id$";
#endif /* lint */

#include <stdio.h>

char program[] = "/usr/local/bin/newpolicy.pl";

int main( int argc, char *argv[]) 
{
    char *empty[] = { NULL };

    /* Call with empty argument vector and empty environment.	*/
    return execve(program, empty, empty); 
} 

