# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Router-R3.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 45;
BEGIN { use_ok('Router::R3') };

#########################

# Insert your test code below, the Test::More module is use