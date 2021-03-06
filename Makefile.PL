use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer::Plugin::LDAP',
    AUTHOR              => q{Stefan Hornburg (Racke) <racke@linuxia.de>},
    VERSION_FROM        => 'lib/Dancer/Plugin/LDAP.pm',
    ABSTRACT_FROM       => 'lib/Dancer/Plugin/LDAP.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Dancer' => 1.3098,
        'Net::LDAP' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer-Plugin-LDAP-*' },
    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources => {
            repository => {
                type => 'git',
                url  => 'https://github.com/racke/Dancer-Plugin-LDAP.git',
                web  => 'https://github.com/racke/Dancer-Plugin-LDAP',
                bugtracker  => 'http://github.com/racke/Dancer-Plugin-LDAP/issues',
            },
        },
    },
);
