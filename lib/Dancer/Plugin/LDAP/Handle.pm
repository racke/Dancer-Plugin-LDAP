package Dancer::Plugin::LDAP::Handle;

use strict;
use Carp;
use Net::LDAP;
use Net::LDAP::Util qw(escape_dn_value escape_filter_value ldap_explode_dn);

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
	my ($self, $dn, $ref, %opts) = @_;
	my ($mesg);

	Dancer::Logger::debug("LDAP insert, dn: ", $dn, "; data: ", $ref);
	
	$mesg = $self->add($dn, attr => [%$ref]);

	if ($mesg->code) {
		return $self->_failure('insert', $mesg, $opts{errors});
	}

	return $dn;
}

=head2 quick_select

quick_select performs a search in the LDAP directory.

The simplest form is to just specify the filter:

    ldap->quick_select({objectClass => 'inetOrgPerson'});

This retrieves all records of the object class C<inetOrgPerson>.

A specific record can be fetched by using the distinguished name (DN)
as only key in the hash reference:

    ldap->quick_select({dn => 'uid=racke@linuxia.de,dc=linuxia,dc=de'});

The base of your search can be passed as first argument, otherwise
the base defined in your settings will be used.

    ldap->quick_select('dc=linuxia,dc=de', {objectClass => 'inetOrgPerson'});

You may add any options supported by the Net::LDAP search method,
e.g.:

    ldap->quick_select('dc=linuxia,dc=de', {objectClass => 'inetOrgPerson'},
        scope => 'one');

=head3 Attributes

In addition, there is a C<values> option which determines how values
for LDAP attributes are fetched:

=over 4

=item first

First value of each attribute.

=item last

Last value of each attribute.

=item asref

Values as array reference.

=back

=cut

sub quick_select {
	my ($self) = shift;
	my ($table, $spec_ref, $mesg, @conds, $filter, $key, $value,
	    @search_args, @results, $safe_value, %opts, @ldap_args);

	if (ref($_[0]) eq 'HASH') {
		# search specification is first argument
		$table = $self->base();
	}
	else {
		$table = shift;
	}
	
	$spec_ref = shift;

	# check remaining parameters
	%opts = (values => 'first');

	while (@_ > 0) {
	    $key = shift;

	    if (exists $opts{$key}) {
		$opts{$key} = shift;
	    }
	    else {
		push(@ldap_args, $key, shift);
	    }
	}

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
			# escape filter value first
			$safe_value = escape_filter_value($value);
			push (@conds, "($key=$safe_value)");
		}
	}

	if (@conds > 1) {
		$filter = '(&' . join('', @conds) . ')';
	}
	elsif (exists $spec_ref->{dn}) {
		# lookup of distinguished name
		$filter = '(objectClass=*)';
		$table = $spec_ref->{dn};
		push (@_, scope => 'base');
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
		    if ($opts{values} eq 'asref') {
			# all attribute values as array reference
			$token->{$attr} = $entry->get_value($attr, asref => 1);
		    }
		    elsif ($opts{values} eq 'last') {
			# last attribute value
			my $value_ref =  $entry->get_value($attr, asref => 1);
			$token->{$attr} = defined($value_ref) ? $value_ref->[-1] : undef;
		    }
		    else {
			# first attribute value
			$token->{$attr} = $entry->get_value($attr);
		    }
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

=head2 quick_compare $type $a $b $pos

=cut

sub quick_compare {
    my ($type, $a, $b, $pos) = @_;

    if ($type eq 'dn') {
	# explode both distinguished names
	my ($dn_a, $dn_b, $href_a, $href_b, $cmp);

	$dn_a = ldap_explode_dn($dn_a);
	$dn_b = ldap_explode_dn($dn_b);

	if (@$dn_a > @$dn_b) {
	    return 1;
	}
	elsif (@$dn_a < @$dn_b) {
	    return -1;
	}

	# check entries, starting from $pos
	$pos ||= 0;

	for (my $i = $pos; $i < @$dn_a; $i++) {
	    $href_a = $dn_a->[$i];
	    $href_b = $dn_b->[$i];

	    for my $k (keys %$href_a) {
		unless (exists($href_b->{$k})) {
		    return 1;
		}
		
		if ($cmp = $href_a->{$k} cmp $href_b->{$k}) {
		    return $cmp;
		}

		delete $href_b->{$k};
	    }

	    if (keys %$href_b) {
		return -1;
	    }
	}

	return 0;
    }
}

=head2 quick_update $dn $replace

=cut

sub quick_update {
	my ($self, $dn, $spec_ref) = @_;
	my ($mesg);

	Dancer::Logger::debug("LDAP update, dn: ", $dn, "; data: ", $spec_ref);
	
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

=head2 rename $old_dn $new_dn

Change DN of a LDAP record from $old_dn to $new_dn.

=cut

sub rename {
    my ($self, $old_dn, $new_dn) = @_;
    my ($ldret, $old_ref, $new_ref, $rdn, $new_rdn, $superior, $ret);

    $old_ref = $self->dn_split($old_dn, hash => 1);
    $new_ref = $self->dn_split($new_dn, hash => 1);

    if (@$new_ref == 1) {
	# got already relative DN
	$new_rdn = $new_dn;
    }
    else {
	# relative DN is first
	$rdn = shift @$new_ref;

	# check if it needs to move in the tree
	if ($self->compare($old_dn, $new_dn, 1)) {
	    die "Different LDAP trees.";
	}

	$new_rdn = join('+', map {$_=$rdn->{$_}} keys %$rdn);
    }

    Dancer::Logger::debug("LDAP rename from $old_dn to $new_rdn.");

    # change distinguished name
    $ldret = $self->moddn ($old_dn, newrdn => $new_rdn);

    if ($ldret->code) {
	return $self->_failure('rename', $ldret);
    }

    # change attribute
 #   return $self->quick_update('');

    shift @$old_ref;
    return $self->dn_join($new_rdn, @$old_ref);
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

=head2 dn_split $dn %options

=cut

sub dn_split {
    my ($self, $dn, %options) = @_;
    my ($dn_ref, @out);

    $dn_ref = ldap_explode_dn($dn);
    Dancer::Logger::debug("Result for $dn: ", $dn_ref || 'N/A');
    if ($options{hash}) {
	return $dn_ref;
    }
    
    for my $rdn (@$dn_ref) {
	push (@out, join '+', 
	      map {$_ = escape_dn_value($rdn->{$_})} keys %$rdn);
    }

    return join(',', @out);
}

=head2 dn_join $rdn1 $rdn2 ...

=cut

sub dn_join {
    my ($self, @rdn_list) = @_;
    my (@out);

    for my $rdn (@rdn_list) {
	if (ref($rdn) eq 'HASH') {
	    push (@out, join '+', 
		  map {"$_ =" . escape_dn_value($rdn->{$_})} keys %$rdn);
	}
	else {
	    push (@out, $rdn);
	}
    }

    return join(',', @out);
}

=head2 dn_value $dn $pos $attribute

Returns DN attribute value from $dn at position $pos,
matching attribute name $attribute.

$pos and $attribute are optional.

Returns undef in the following cases:

* invalid DN
* $pos exceeds number of entries in the DN
* attribute name doesn't match $attribute

Examples:

    ldap->dn_value('ou=Testing,dc=linuxia,dc=de');

    Testing

    ldap->dn_value('ou=Testing,dc=linuxia,dc=de', 1);

    linuxia

=cut

sub dn_value {
    my ($self, $dn, $pos, $attribute) = @_;
    my ($new_ref, $entry);

    $new_ref = ldap_explode_dn($dn);
    $pos ||= 0;

    unless (defined $new_ref) {
	return;
    }

    if ($pos >= @$new_ref) {
	return;
    }

    $entry = $new_ref->[$pos];

    if (defined $attribute) {
	# keys are by default uppercase
	$attribute = uc($attribute);

	if (exists $entry->{$attribute}) {
	    return $entry->{$attribute};
	}

	return;
    }

    return $entry->{values(%$entry)->[0]};
}

sub _failure {
	my ($self, $op, $mesg, $options) = @_;

	if ($options) {
		if (ref($options) eq 'HASH') {
			if ($mesg->code == 68) {
				# "Already exists"
				if ($options->{exists}) {
					return;
				}
			}
		}
	}

	die "LDAP $op failed (" . $mesg->code . ") with " . $mesg->error;
}

1;

