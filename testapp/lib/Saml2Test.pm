package Saml2Test;
use Dancer ':syntax';

use Net::SAML2;
use MIME::Base64 qw/ decode_base64 /;

our $VERSION = '0.1';

get '/' => sub {
	template 'index';
};

get '/login' => sub {
        my $idp = Net::SAML2::IdP->new_from_url(config->{idp});

        my $sp = Net::SAML2::SP->new(
		id   => 'http://localhost:3000',
                url  => 'http://localhost:3000',
                cert => 'sign-nopw-cert.pem',
		key  => 'sign-nopw-cert.pem',
        );

        my $sso_url = $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
        my $authnreq = $sp->authn_request($idp->entityID)->as_xml;

        my $redirect = Net::SAML2::Binding::Redirect->new(
                key => 'sign-nopw-cert.pem',
                url => $sso_url,
        );

        my $url = $redirect->sign_request($authnreq);
        redirect $url, 302;

        return "Redirected\n";
};

get '/logout-local' => sub {
	redirect '/', 302;
};

get '/logout-redirect' => sub {
        my $idp = Net::SAML2::IdP->new_from_url(config->{idp});
        my $slo_url = $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
        
        my $sp = Net::SAML2::SP->new(
		id   => 'http://localhost:3000',
                url  => 'http://localhost:3000',
                cert => 'sign-nopw-cert.pem',
        );
        my $logoutreq = $sp->logout_request(
		$idp->entityID, params->{nameid}, params->{session}
	)->as_xml;

        my $redirect = Net::SAML2::Binding::Redirect->new(
                key => 'sign-nopw-cert.pem',
                url => $slo_url,
        );

        my $url = $redirect->sign_request($logoutreq);
        redirect $url, 302;

        return "Redirected\n";
};

get '/logout-soap' => sub {
        my $idp = Net::SAML2::IdP->new_from_url(config->{idp});
        my $slo_url = $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:SOAP');
	my $idp_cert = $idp->cert('signing');
        
        my $sp = Net::SAML2::SP->new(
		id   => 'http://localhost:3000',
                url  => 'http://localhost:3000',
                cert => 'sign-nopw-cert.pem',
        );
        my $logoutreq = $sp->logout_request(
		$idp->entityID, params->{nameid}, params->{session}
	)->as_xml;

        my $soap = Net::SAML2::Binding::SOAP->new(
                key	 => 'sign-nopw-cert.pem',
		cert	 => 'sign-nopw-cert.pem',
                url	 => $slo_url,
		idp_cert => $idp_cert,
        );

        my $res = $soap->request($logoutreq);

        redirect '/', 302;
        return "Redirected\n";
};

post '/consumer-post' => sub {
        my $post = Net::SAML2::Binding::POST->new(
		cacert => 'saml_cacert.pem',
	);
        my $ret = $post->handle_response(
                params->{SAMLResponse}
        );
        
        if ($ret) {
                my $assertion = Net::SAML2::Protocol::Assertion->new(
                        xml => decode_base64(params->{SAMLResponse})
                );

                template 'user', { assertion => $assertion };
        }
        else {
                return "<html><pre>Bad Assertion</pre></html>";
        }
};

get '/consumer-artifact' => sub {
        my $idp = Net::SAML2::IdP->new_from_url(config->{idp});
	my $idp_cert = $idp->cert('signing');
        my $art_url  = $idp->art_url('urn:oasis:names:tc:SAML:2.0:bindings:SOAP');

	my $artifact = params->{SAMLart};

        my $sp = Net::SAML2::SP->new(
		id   => 'http://localhost:3000',
                url  => 'http://localhost:3000',
                cert => 'sign-nopw-cert.pem',
        );
	my $request = $sp->artifact_request($idp->entityID, $artifact)->as_xml;

        my $soap = Net::SAML2::Binding::SOAP->new(
                url	 => $art_url,
                key	 => 'sign-private.pem',
                cert	 => 'sign-certonly.pem',
		idp_cert => $idp_cert
        );
        my $response = $soap->request($request);

        if ($response) {
                my $assertion = Net::SAML2::Protocol::Assertion->new(
                        xml => $response
                );
                
                template 'user', { assertion => $assertion };
        }
        else {
                return "<html><pre>Bad Assertion</pre></html>";
        }
};

get '/sls-redirect-response' => sub {
        my $post = Net::SAML2::Binding::Redirect->new;
        my $ret = $post->handle_response(
                params->{SAMLResponse}
        );
        
        redirect '/', 302;
        return "Redirected\n";
};

get '/metadata.xml' => sub {
        my $sp = Net::SAML2::SP->new(
		id   => 'http://localhost:3000',
                url  => 'http://localhost:3000',
                cert => 'sign-nopw-cert.pem',
        );
        return $sp->metadata;
};

true;
