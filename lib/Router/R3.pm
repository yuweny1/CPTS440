
package Router::R3;

use 5.006;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

our $VERSION = '0.011001';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Router::R3::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Router::R3', $VERSION);

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!
