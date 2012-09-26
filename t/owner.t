#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $head);

############################################################
$title = 'Check for owners with duplicate alias names';
############################################################

$in = <<END;
admin:a = { email = a\@b.c; }

owner:xx = {
 alias = X Quadrat;
 admins = a;
}

owner:x2 = {
 alias = X Quadrat;
 admins = a;
}
END

$out = <<END;
Error: Name conflict between owners
 - owner:xx with alias 'X Quadrat'
 - owner:x2 with alias 'X Quadrat'
Error: Topology seems to be empty
Aborted
END

eq_or_diff(compile_err($in), $out, $title);

############################################################
$title = 'Check for owners with conflicting name and alias name';
############################################################

$in = <<END;
admin:a = { email = a\@b.c; }

owner:y = {
 alias = z;
 admins = a;
}

owner:z = {
 admins = a;
}
END

$out = <<END;
Error: Name conflict between owners
 - owner:z
 - owner:y with alias 'z'
Error: Topology seems to be empty
Aborted
END

eq_or_diff(compile_err($in), $out, $title);

############################################################
done_testing;
