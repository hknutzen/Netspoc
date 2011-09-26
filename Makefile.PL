use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	      'NAME'          => 'Netspoc',
#              'VERSION'       => 3.3,
	      'VERSION_FROM'  => 'lib/Netspoc.pm',
	      'EXE_FILES'     => [ qw(bin/netspoc 
				      bin/cut-netspoc 
				      bin/print-group
				      bin/rename-netspoc
				      ) ],
	      'INSTALLSCRIPT' => '/usr/local/bin',
);
