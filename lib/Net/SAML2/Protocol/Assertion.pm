package Net::SAML2::Protocol::Assertion;
use Moose;
use MooseX::Types::Moose qw/ Str HashRef ArrayRef /;

with 'Net::SAML2::Role::Templater',
     'Net::SAML2::Role::ProtocolMessage';

=head1 NAME

Net::SAML2::Protocol::Assertion - SAML2 assertion object

=head1 SYNOPSIS

  my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
    xml => decode_base64($SAMLResponse)
  );

=cut

has 'attributes' => (isa => HashRef[ArrayRef], is => 'ro', required => 1);
has 'session'    => (isa => Str, is => 'ro', required => 1);
has 'nameid'     => (isa => Str, is => 'ro', required => 1);

=head1 METHODS

=cut

=head2 new_from_xml( ... )

Constructor. Creates an instance of the Assertion object, parsing the
given XML to find the attributes, session and nameid. 

=cut

sub new_from_xml { 
        my ($class, %args) = @_;

        my $xpath = XML::XPath->new( xml => $args{xml} );
        $xpath->set_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');

	my $attributes = {};
        for my $node ($xpath->findnodes('//saml:Assertion/saml:AttributeStatement/saml:Attribute')) {
		my @values = $node->findnodes('saml:AttributeValue');
                $attributes->{$node->getAttribute('Name')} = [
			map { $_->string_value } @values
		];
        }
        
        my $self = $class->new(
                attributes => $attributes,
                session    => $xpath->findvalue('//saml:AuthnStatement/@SessionIndex')->value,
                nameid     => $xpath->findvalue('//saml:Subject/saml:NameID')->value,
        );
	
        return $self;
}

=head2 name

Returns the CN attribute, if provided.

=cut

sub name {
        my ($self) = @_;
	return $self->attributes->{CN}->[0];
}

1;
