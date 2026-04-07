package de.gupta.security.hermes.api;

import de.gupta.security.hermes.api.hmac.HmacTokenExchangeServiceFactory;
import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.api.TokenVerifier;

public final class TokenExchangeServiceFactory
{
	public static <User> TokenExchangeService hmac(final TokenVerifier upstreamTokenVerifier,
	                                               final TokenIssuancePolicy issuancePolicy,
	                                               final String issuerSecret,
	                                               final TokenExchangeConfiguration<User> configuration)
	{
		return HmacTokenExchangeServiceFactory.create(upstreamTokenVerifier,
				issuancePolicy,
				issuerSecret,
				configuration);
	}

	public static <User> TokenExchangeService hmac(final TokenVerificationPolicy upstreamVerificationPolicy,
	                                               final String upstreamIssuerSecret,
	                                               final TokenIssuancePolicy issuancePolicy,
	                                               final String issuerSecret,
	                                               final TokenExchangeConfiguration<User> configuration)
	{
		return HmacTokenExchangeServiceFactory.create(upstreamVerificationPolicy,
				upstreamIssuerSecret,
				issuancePolicy,
				issuerSecret,
				configuration);
	}

	private TokenExchangeServiceFactory()
	{
	}
}