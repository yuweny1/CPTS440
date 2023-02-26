#!/usr/bin/perl

use strict;
use warnings;

use lib qw(/home/cindy/perl5/lib/perl);
use Data::Dumper;

use Router::R3;

#Router::R3::test();
my $t = Router::R3->new(
    '/foo/bar' => 2,
    '/zoo' => 1,
    '/bar' => 3,
    '/post/{id}' => 4,
  