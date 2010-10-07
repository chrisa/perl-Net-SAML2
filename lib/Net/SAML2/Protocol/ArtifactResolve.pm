package Net::SAML2::Protocol::ArtifactResolve;
use strict;
use warnings;

=head1 NAME

Net::SAML2::Protocol::ArtifactResolve - ArtifactResolve protocol class.

=head1 SYNOPSIS

  my $resolver = Net::SAML2::Binding::ArtifactResolve->new(
    issuer => 'http://localhost:3000',
  );

  my $response = $resolver->resolve(params->{SAMLart});

=head1 METHODS

=cut

=head2 new( ... )

Constructor. Returns an instance of the ArtifactResolve request for
the given issuer and artifact.

Arguments:

 * issuer - the issuing SP's identity URI
 * artifact - the artifact to be resolved
 * issueinstant - a DateTime for "now"
 * destination - the IdP's identity URI

=cut

sub new {
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        $self->{issuer} = $args{issuer};
        $self->{artifact} = $args{artifact};
        $self->{destination}  = $args{destination};
	$self->{issueinstant} = $args{issueinstant};

        return $self;
}

=head2 as_xml

Returns the ArtifactResolve request as XML.

=cut

sub as_xml {
        my ($self) = @_;

	my $issueinstant = DateTime::Format::XSD->format_datetime(
		$self->{issueinstant}
	);

        my $xml = <<"EOXML";
 <samlp:ArtifactResolve
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"   
   ID="_cce4ee769ed970b501d680f697989d14"
   IssueInstant="$issueinstant"
   Destination="$self->{destination}" 
   ProviderName="My SP's human readable name."
   Version="2.0">
   <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">$self->{issuer}</saml:Issuer>
   <samlp:Artifact>$self->{artifact}</samlp:Artifact>
 </samlp:ArtifactResolve>
EOXML

	return $xml;
}

1;
