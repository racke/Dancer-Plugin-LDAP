package Dancer::Plugin::LDAP;

use 5.006;
use strict;
use warnings;

use Dancer::Plugin;
use Net::LDAP;
use Dancer::Plugin::LDAP::Handle;

=head1 NAME

Dancer::Plugin::LDAP - LDAP plugin for Dancer micro framework

=head1 VERSION

Version 0.0001

=cut

our $VERSION = '0.0001';


=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Dancer::Plugin;
    use Dancer::Plugin::LDAP;

    my $foo = Dancer::Plugin::LDAP->new();
    ...

=head1 CONFIGURATION

    plugins:
        LDAP:
            uri: 'ldap://127.0.0.1:389/'
            base: 'dc=linuxia,dc=de'

=head1 SUBROUTINES/METHODS

=cut

my $settings = undef;
my %handles;
my $def_handle = {};

register ldap => sub {
	my $arg = shift;

	_load_ldap_settings() unless $settings;
	
	# The key to use to store this handle in %handles.  This will be either the
    # name supplied to database(), the hashref supplied to database() (thus, as
    # long as the same hashref of settings is passed, the same handle will be
    # reused) or $def_handle if database() is called without args:
    my $handle_key;
    my $conn_details; # connection settings to use.
    my $handle;

    # Accept a hashref of settings to use, if desired.  If so, we use this
    # hashref to look for the handle, too, so as long as the same hashref is
    # passed to the database() keyword, we'll reuse the same handle:
    if (ref $arg eq 'HASH') {
        $handle_key = $arg;
        $conn_details = $arg;
    } else {
        $handle_key = defined $arg ? $arg : $def_handle;
        $conn_details = _get_settings($arg);
        if (!$conn_details) {
            Dancer::Logger::error(
                "No LDAP settings for " . ($arg || "default connection")
            );
            return;
        }
    }

#	Dancer::Logger::debug("Details: ", $conn_details);

    # To be fork safe and thread safe, use a combination of the PID and TID (if
    # running with use threads) to make sure no two processes/threads share
    # handles.  Implementation based on DBIx::Connector by David E. Wheeler.
    my $pid_tid = $$;
    $pid_tid .= '_' . threads->tid if $INC{'threads.pm'};

    # OK, see if we have a matching handle
    $handle = $handles{$pid_tid}{$handle_key} || {};

    if ($handle->{dbh}) {
        if ($conn_details->{connection_check_threshold} &&
            time - $handle->{last_connection_check}
            < $conn_details->{connection_check_threshold}) 
        {
            return $handle->{dbh};
        } else {
            if (_check_connection($handle->{dbh})) {
                $handle->{last_connection_check} = time;
                return $handle->{dbh};
            } else {
 #               Dancer::Logger::debug(
 #                   "Database connection went away, reconnecting"
#                );
                if ($handle->{dbh}) { $handle->{dbh}->disconnect; }
                return $handle->{dbh}= _get_connection($conn_details);

            }
        }
    } else {
        # Get a new connection
        if ($handle->{dbh} = _get_connection($conn_details)) {
            $handle->{last_connection_check} = time;
            $handles{$pid_tid}{$handle_key} = $handle;
#			Dancer::Logger::debug("Handle: ", $handle);
            return $handle->{dbh};
        } else {
            return;
        }
    }
};

register_plugin;

# Try to establish a LDAP connection based on the given settings
sub _get_connection {
	my $settings = shift;
	my ($ldap, $ldret);

	unless ($ldap = Net::LDAP->new($settings->{uri})) {
		Dancer::Logger::error('LDAP connection failed - ' . $@);
		return;
	}

	$ldret = $ldap->bind($settings->{bind},
						 password => $settings->{password});

	if ($ldret->code) {
		Dancer::Logger::error('LDAP bind failed (' . $ldret->code . '): '
							  . $ldret->error);
		return;
	}
	
	# pass reference to the settings
	$ldap->{dancer_settings} = $settings;
	
	return bless $ldap, 'Dancer::Plugin::LDAP::Handle';
}

sub _check_connection {
	return 1;
}

sub _get_settings {
    my $name = shift;
    my $return_settings;

    # If no name given, just return the default settings
    if (!defined $name) {
        $return_settings = { %$settings };
    } else {
        # If there are no named connections in the config, bail now:
        return unless exists $settings->{connections};


        # OK, find a matching config for this name:
        if (my $settings = $settings->{connections}{$name}) {
            $return_settings = { %$settings };
        } else {
            # OK, didn't match anything
            Dancer::Logger::error(
                "Asked for a database handle named '$name' but no matching  "
               ."connection details found in config"
            );
        }
    }

    # We should have soemthing to return now; make sure we have a
    # connection_check_threshold, then return what we found.  In previous
    # versions the documentation contained a typo mentioning
    # connectivity-check-threshold, so support that as an alias.
    if (exists $return_settings->{'connectivity-check-threshold'}
        && !exists $return_settings->{connection_check_threshold})
    {
        $return_settings->{connection_check_threshold}
            = delete $return_settings->{'connectivity-check-threshold'};
    }

    $return_settings->{connection_check_threshold} ||= 30;
    return $return_settings;

}

sub _load_ldap_settings { $settings = plugin_setting; }

=head1 AUTHOR

Stefan Hornburg (Racke), C<< <racke at linuxia.de> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-dancer-plugin-ldap at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Dancer-Plugin-LDAP>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Dancer::Plugin::LDAP


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Dancer-Plugin-LDAP>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Dancer-Plugin-LDAP>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Dancer-Plugin-LDAP>

=item * Search CPAN

L<http://search.cpan.org/dist/Dancer-Plugin-LDAP/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2011 Stefan Hornburg (Racke).

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Dancer::Plugin::LDAP
