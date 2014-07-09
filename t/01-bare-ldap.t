use strict;
use warnings;
use Net::LDAP;
use Test::More;
use File::Spec;
use YAML qw/DumpFile/;

# Thanks to this http://blog.stuartlewis.com/2008/07/07/test-ldap-service/

my $ldap = Net::LDAP->new('ldap://ldap.testathon.net');

my $mesg = $ldap->bind('cn=stuart,OU=users,DC=testathon,DC=net',
                       password => 'stuart');


if ($mesg->code) {
    plan skip_all => "Test box error: " . $mesg->error;
}
else {
    plan tests => 1;
}

$mesg = $ldap->search(base => 'OU=users,DC=testathon,DC=net',
                      filter => "(&(sn=*))");

my $counter = 0;
foreach my $entry ($mesg->entries) {
    $counter++;
    $entry->dump;
}

ok($counter, "Found $counter entries");
my $conffile = File::Spec->catfile(t => 'ldap.conf');
my $conf = {
            uri => 'ldap://ldap.testathon.net:389/',
            base => 'DC=testathon,DC=net',
            bind => 'cn=stuart,OU=users,DC=testathon,DC=net',
            password => 'stuart',
           };
DumpFile($conffile, $conf);

