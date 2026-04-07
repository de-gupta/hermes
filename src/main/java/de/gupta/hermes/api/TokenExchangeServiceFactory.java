package de.gupta.hermes.api;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.api.TokenVerifier;
import de.gupta.hermes.api.hmac.HmacTokenExchangeServiceFactory;

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