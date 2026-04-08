package de.gupta.security.hermes.application.service;

import de.gupta.security.hermes.api.TokenExchangeConfiguration;
import de.gupta.security.hermes.api.TokenIssuancePolicy;
import de.gupta.security.themis.api.TokenVerifier;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Objects;

public final class InternalTokenExchangeServiceFactory
{
	public static <User> InternalTokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                                         final TokenIssuancePolicy issuancePolicy,
	                                                         final String issuerSecret,
	                                                         final TokenExchangeConfiguration<User> configuration)
	{
		return InternalTokenExchangeServiceImpl.create(upstreamTokenVerifier,
				issuancePolicy,
				Keys.hmacShaKeyFor(Objects.requireNonNull(issuerSecret, "issuerSecret must not be null")
				                          .getBytes(StandardCharsets.UTF_8)),
				configuration);
	}

	public static <User> InternalTokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                                         final TokenIssuancePolicy issuancePolicy,
	                                                         final Key issuerSigningKey,
	                                                         final TokenExchangeConfiguration<User> configuration)
	{
		return InternalTokenExchangeServiceImpl.create(upstreamTokenVerifier,
				issuancePolicy,
				issuerSigningKey,
				configuration);
	}

	private InternalTokenExchangeServiceFactory()
	{
	}
}