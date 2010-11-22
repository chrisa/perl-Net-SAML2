use Test::More;
use strict;
use warnings;
use Net::SAML2;

my $lor = Net::SAML2::Protocol::LogoutRequest->new(
        issuer => 'http://some/sp',
        destination => 'http://some/idp',
        nameid => 'name-to-log-out',
        session => 'session-to-log-out',
);
ok($lor);
my $xml = $lor->as_xml;
ok($xml);
#diag($xml);

ok(qr/ID=".+"/, $xml);
ok(qr/IssueInstant=".+"/, $xml);

done_testing;
