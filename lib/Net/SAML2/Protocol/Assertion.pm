package Net::SAML2::Protocol::Assertion;
use strict;
use warnings;

use XML::XPath;

sub new { 
        my ($class, %args) = @_;
        my $self = bless {}, $class;

        my $xpath = XML::XPath->new( xml => $args{xml} );
        $xpath->set_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');

        $self->{attributes} = {};
        for my $node ($xpath->findnodes('//saml:Assertion/saml:AttributeStatement/saml:Attribute')) {
                $self->{attributes}->{$node->getAttribute('Name')} = 
                     $node->findvalue('saml:AttributeValue')->value;
        }
        
        $self->{session} = $xpath->findvalue('//saml:AuthnStatement/@SessionIndex')->value;
        $self->{nameid}  = $xpath->findvalue('//saml:Subject/saml:NameID')->value;

        return $self;
}

sub attributes {
        my ($self) = @_;
        return $self->{attributes};
}

sub session {
        my ($self) = @_;
        return $self->{session};
}

sub nameid {
        my ($self) = @_;
        return $self->{nameid};
}

sub name {
        my ($self) = @_;
        return $self->{attributes}->{CN};
}

1;
