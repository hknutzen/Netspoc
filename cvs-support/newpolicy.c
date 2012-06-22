/* Wrapper script for newpolicy.pl				*/
/* This should be installed setuid and setgid.			*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char program[] = "/usr/local/bin/newpolicy.pl";

int main( int argc, char *argv[]) 
{
    char cvsroot[500];
    char lang[500];
    char CVSROOT[] = "CVSROOT=";
    char LANG[] = "LANG=";
    strcat(cvsroot, CVSROOT);
    strcat(lang, LANG);
    strncat(cvsroot, getenv("CVSROOT"), sizeof(cvsroot)-sizeof(CVSROOT)-1);
    strncat(lang, getenv("LANG"), sizeof(lang)-sizeof(LANG)-1);

    char *empty[] = { NULL };
    char *env[] = { cvsroot, lang, NULL };

    /* Call with empty argument vector and new environment. */
    return execve(program, empty, env); 
} 
