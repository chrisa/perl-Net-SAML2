package Net::SAML2::IdP;
use strict;
use warnings;

use HTTP::Request::Common;
use LWP::UserAgent;
use XML::XPath;

sub new {
        my ($class, $url) = @_;
        my $self = bless {}, $class;
        
        my $req = GET $url;
        my $ua = LWP::UserAgent->new;

        my $res = $ua->request($req);
        die "no metadata" unless $res->is_success;
        my $xml = $res->content;

        my $xpath = XML::XPath->new( xml => $xml );
        $xpath->set_namespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        my @ssos = $xpath->findnodes('//md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService');
        for my $sso (@ssos) {
                my $binding = $sso->getAttribute('Binding');
                $self->{SSO}->{$binding} = $sso->getAttribute('Location');
        }

        my @slos = $xpath->findnodes('//md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService');
        for my $slo (@slos) {
                my $binding = $slo->getAttribute('Binding');
                $self->{SLO}->{$binding} = $slo->getAttribute('Location');
        }

        my @arts = $xpath->findnodes('//md:EntityDescriptor/md:IDPSSODescriptor/md:ArtifactResolutionService');
        for my $art (@arts) {
                my $binding = $art->getAttribute('Binding');
                $self->{Art}->{$binding} = $art->getAttribute('Location');
        }
        
        return $self;
}

sub sso_url {
        my ($self, $binding) = @_;
        return $self->{SSO}->{$binding};
}

sub slo_url {
        my ($self, $binding) = @_;
        return $self->{SLO}->{$binding};
}

sub art_url {
        my ($self, $binding) = @_;
        return $self->{Art}->{$binding};
}

1;
