package de.gupta.hermes.application.service;

import de.gupta.commons.security.api.TokenVerifier;
import de.gupta.hermes.api.TokenExchangeConfiguration;
import de.gupta.hermes.api.TokenIssuancePolicy;

public final class TokenExchangeServiceFactory
{
	public static <User> TokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                                 final TokenIssuancePolicy issuancePolicy,
	                                                 final String issuerSecret,
	                                                 final TokenExchangeConfiguration<User> configuration)
	{
		return TokenExchangeServiceImpl.create(upstreamTokenVerifier, issuancePolicy, issuerSecret, configuration);
	}

	private TokenExchangeServiceFactory()
	{
	}
}
