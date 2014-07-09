use strict;
use warnings;

use Test::More;
use File::Spec;
use YAML qw/LoadFile/;
use Data::Dumper;

use Dancer qw/:tests/;
use Dancer::Plugin::LDAP;

use Dancer::Test;

set logger => 'capture';
set log => 'debug';

my $conffile = File::Spec->catfile(t => 'ldap.conf');
if (-f $conffile) {
    plan tests => 9;
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
ok(!ldap("not existent connection"), "Wrong connection yields undef");
ldap->dancer_debug("Hey", "ho", "let's go");
ldap->dancer_error("Error", "found");

my $expected_logs = [
                     {
                      'level' => 'debug',
                      'message' => 'LDAP search: [\'base\',\'DC=testathon,DC=net\',\'filter\',\'(cn=stuart)\']'
                     },
                     {
                      'level' => 'debug',
                      'message' => 'LDAP rebind to cn=stuart,OU=users,DC=testathon,DC=net.'
                     },
                     {
                      'level' => 'error',
                      'message' => 'No LDAP settings for not existent connection'
                     },
                     {
                      'level' => 'debug',
                      'message' => 'Heyholet\'s go'
                     },
                     {
                      'level' => 'error',
                      'message' => 'Errorfound'
                     }
                    ];
is_deeply(read_logs, $expected_logs, "Logging appears ok");
