package Net::SAML2::Protocol::Assertion;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Protocol::Assertion - SAML2 assertion object

=head1 SYNOPSIS

  my $assertion = Net::SAML2::Protocol::Assertion->new(
    xml => decode_base64($SAMLResponse)
  );

=head1 METHODS

=cut

use XML::XPath;

=head2 new( ... )

Constructor. Creates an instance of the Assertion object, parsing the
given XML to find the attributes, session and nameid. 

=cut

sub new { 
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        my $xpath = XML::XPath->new( xml => $args{xml} );
        $xpath->set_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');

        $self->{attributes} = {};
        for my $node ($xpath->findnodes('//saml:Assertion/saml:AttributeStatement/saml:Attribute')) {
		my @values = $node->findnodes('saml:AttributeValue');
                $self->{attributes}->{$node->getAttribute('Name')} = [
			map { $_->string_value } @values
		];
        }
        
        $self->{session} = $xpath->findvalue('//saml:AuthnStatement/@SessionIndex')->value;
        $self->{nameid}  = $xpath->findvalue('//saml:Subject/saml:NameID')->value;

        return $self;
}

=head2 attributes()

Returns a hash of SAML attributes found in the assertion.

=cut

sub attributes {
        my ($self) = @_;
        return $self->{attributes};
}

=head2 session()

Returns the SAML session identifier, which may be used in a
LogoutRequest to terminate this session.

=cut

sub session {
        my ($self) = @_;
        return $self->{session};
}

=head2 nameid()

Returns the nameid in the Assertion.

=cut

sub nameid {
        my ($self) = @_;
        return $self->{nameid};
}

=head2 name

Returns the CN attribute, if provided.

=cut

sub name {
        my ($self) = @_;
        return $self->{attributes}->{CN}->[0];
}

1;
