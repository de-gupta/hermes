package de.gupta.security.hermes.application.service;

import de.gupta.commons.security.api.TokenVerifier;
import de.gupta.security.hermes.api.TokenExchangeConfiguration;
import de.gupta.security.hermes.api.TokenIssuancePolicy;

public final class InternalTokenExchangeServiceFactory
{
	public static <User> InternalTokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                                         final TokenIssuancePolicy issuancePolicy,
	                                                         final String issuerSecret,
	                                                         final TokenExchangeConfiguration<User> configuration)
	{
		return InternalTokenExchangeServiceImpl.create(upstreamTokenVerifier,
				issuancePolicy,
				issuerSecret,
				configuration);
	}

	private InternalTokenExchangeServiceFactory()
	{
	}
}