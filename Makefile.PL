use 5.006;
use ExtUtils::MakeMaker;
use strict;
use warnings;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Router::R3',
    VERSION_FROM      => 'lib/Router/R3.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these ne