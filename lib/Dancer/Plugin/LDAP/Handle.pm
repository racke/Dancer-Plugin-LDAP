package Dancer::Plugin::LDAP::Handle;

use strict;
use Carp;
use Net::LDAP;
use base qw(Net::LDAP);

our $VERSION = '0.0001';

=head1 METHODS

=cut

sub base {
	my $self = shift;

	if (@_) {
		# prepend path
		return join(',', @_, $self->{dancer_settings}->{base});
	}

	return $self->{dancer_settings}->{base};
}

sub quick_insert {
	my ($self, $dn, $ref) = @_;
	my ($mesg);

	Dancer::Logger::debug("LDAP insert, dn: ", $dn, "; data: ", $ref);
	
	$mesg = $self->add($dn, attr => [%$ref]);

	if ($mesg->code) {
		die "LDAP insert failed (" . $mesg->code . ") with " . $mesg->error;
	}

	return $dn;
}

=head2 quick_select

quick_select performs a search in the LDAP directory.

The simplest form is to just specify the filter:

    ldap->quick_select({objectClass => 'inetOrgPerson'});

This retrieves all records of the object class C<inetOrgPerson>.

The base of your search can be passed as first argument, otherwise
the base defined in your settings will be used.

    ldap->quick_select('dc=linuxia,dc=de', {objectClass => 'inetOrgPerson'});

You may add any options supported by the Net::LDAP search method,
e.g.:

    ldap->quick_select('dc=linuxia,dc=de', {objectClass => 'inetOrgPerson'},
        scope => 'one');

=cut

sub quick_select {
	my ($self) = shift;
	my ($table, $spec_ref, $mesg, @conds, $filter, $key, $value,
		@search_args, @results);

	if (ref($_[0]) eq 'HASH') {
		# search specification is first argument
		$table = $self->base();
	}
	else {
		$table = shift;
	}
	
	$spec_ref = shift;

	while (($key, $value) = each(%$spec_ref)) {
		if (ref($value) eq 'ARRAY') {
			# Operator requested
			if ($value->[0] eq 'exists') {
				if ($value->[1]) {
					# attribute present
					push (@conds, "($key=*)");
				}
				else {
					# attribute missing
					push (@conds, "(!($key=*))");
				}
			}
			else {
				die "Invalid operator $value->[0].";
			}
		}
		else {
			push (@conds, "($key=$value)");
		}
	}

	if (@conds > 1) {
		$filter = '(&' . join('', @conds) . ')';
	}
	else {
		$filter = $conds[0];
	}

	# compose search parameters
	@search_args = (base => $table, filter => $filter, @_);

	Dancer::Logger::debug('LDAP search: ', \@search_args);
	
	$mesg = $self->search(@search_args);

	foreach (my $i = 0; $i < $mesg->count; $i++) {
		my $token = {};
		my $entry = $mesg->entry($i);
		
		$token->{dn} = $entry->dn;
			
		for my $attr ( $entry->attributes ) {
			$token->{$attr} = $entry->get_value($attr);
		}
		
		push(@results, $token);

	}

	if (wantarray) {
		return @results;
	}
	else {
		return $results[0];
	}
}

=head2 quick_update $dn $replace

=cut

sub quick_update {
	my ($self, $dn, $spec_ref) = @_;
	my ($mesg);

	debug("Spec ref: " , $spec_ref);
	
	$mesg = $self->modify(dn => $dn, replace => $spec_ref);

	if ($mesg->code) {
		die "LDAP update failed (" . $mesg->code . ") with " . $mesg->error;
	}

	return $dn;
}

=head2 quick_delete $dn

Deletes entry given by distinguished name $dn.

=cut

sub quick_delete {
	my ($self, $dn) = @_;
	my ($ldret);

	Dancer::Logger::debug("LDAP delete: ", $dn);

	$ldret = $self->delete(dn => $dn);

	if ($ldret->code) {
		die "LDAP delete failed (" . $ldret->code . ") with " . $ldret->error;
	}

	return 1;
}

=head2 rebind

Rebind with credentials from settings.

=cut

sub rebind {
	my ($self) = @_;
	my ($ldret);

	Dancer::Logger::debug("LDAP rebind to $self->{dancer_settings}->{bind}.");
	
	$ldret = $self->bind($self->{dancer_settings}->{bind},
						 password => $self->{dancer_settings}->{password});

	if ($ldret->code) {
		Dancer::Logger::error('LDAP bind failed (' . $ldret->code . '): '
							  . $ldret->error);
		return;
	}

	return $self;
}

1;

