
use strict;
use warnings;



use ExtUtils::MakeMaker 6.30;



my %WriteMakefileArgs = (
  "ABSTRACT" => "A Network Security Policy Compiler",
  "AUTHOR" => "Heinz Knutzen <heinz.knutzen\@dataport.de>",
  "BUILD_REQUIRES" => {
    "File::Temp" => 0,
    "Test::Differences" => 0,
    "Test::More" => 0
  },
  "CONFIGURE_REQUIRES" => {
    "ExtUtils::MakeMaker" => "6.30"
  },
  "DISTNAME" => "Netspoc",
  "EXE_FILES" => [
    "bin/print-group",
    "bin/cut-netspoc",
    "bin/netspoc",
    "bin/rename-netspoc"
  ],
  "LICENSE" => "gpl",
  "NAME" => "Netspoc",
  "PREREQ_PM" => {
    "Encode" => 0,
    "Exporter" => 0,
    "FindBin" => 0,
    "Getopt::Long" => 0,
    "Pod::Usage" => 0,
    "locale" => 0,
    "open" => 0,
    "strict" => 0,
    "utf8" => 0,
    "warnings" => 0
  },
  "VERSION" => "3.017",
  "test" => {
    "TESTS" => "t/*.t"
  }
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.56) } ) {
  my $br = delete $WriteMakefileArgs{BUILD_REQUIRES};
  my $pp = $WriteMakefileArgs{PREREQ_PM};
  for my $mod ( keys %$br ) {
    if ( exists $pp->{$mod} ) {
      $pp->{$mod} = $br->{$mod} if $br->{$mod} > $pp->{$mod};
    }
    else {
      $pp->{$mod} = $br->{$mod};
    }
  }
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);



