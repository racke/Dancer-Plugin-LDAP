use strict;
use warnings;

use Test::More;
use File::Spec;
use YAML qw/LoadFile/;
use Data::Dumper;

use Dancer qw/:tests/;
use Dancer::Plugin::LDAP;
set logger => 'console';
set log => 'debug';

my $conffile = File::Spec->catfile(t => 'ldap.conf');
if (-f $conffile) {
    plan tests => 8;
}
else {
    plan skip_all => 'No configuration file found, probably test box is down';
}

my $conf = LoadFile($conffile);
print Dumper ($conf);
set plugins => { LDAP => $conf };

ok($conf);
print Dumper(ldap);
ok(ldap, "Object exists");
is(ldap->base, $conf->{base}, "Base exists and it matches the conf");
my $result = ldap->quick_select({cn => 'stuart'});

print Dumper($result);
is($result->{cn}, 'stuart');

ok(ldap->rebind, "rebinding works");

my $res = ldap->bind('cn=stuart,OU=users,DC=testathon,DC=net',
                     password => "XXX");

ok($res->code, "Found error code: ". $res->code);
ok($res->error, "Found error:" . $res->error);
ok(!ldap("not existent connection"));
