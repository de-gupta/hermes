package de.gupta.hermes.api;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.api.TokenVerifier;
import de.gupta.commons.security.api.TokenVerifierFactory;
import de.gupta.hermes.adapter.TokenExchangeServiceFacadeFactory;
import de.gupta.hermes.application.service.TokenExchangeServiceFactory;
import de.gupta.hermes.controller.TokenExchangeControllerFactory;

import java.util.Objects;

final class HmacTokenExchangeServiceFactory
{
	static <User> TokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                          final TokenIssuancePolicy issuancePolicy,
	                                          final String issuerSecret,
	                                          final TokenExchangeConfiguration<User> configuration)
	{
		Objects.requireNonNull(upstreamTokenVerifier, "upstreamTokenVerifier must not be null");
		Objects.requireNonNull(issuancePolicy, "issuancePolicy must not be null");
		Objects.requireNonNull(issuerSecret, "issuerSecret must not be null");
		Objects.requireNonNull(configuration, "configuration must not be null");

		return HmacTokenExchangeService.create(
				TokenExchangeControllerFactory.create(
						TokenExchangeServiceFacadeFactory.create(
								TokenExchangeServiceFactory.create(upstreamTokenVerifier,
										issuancePolicy,
										issuerSecret,
										configuration),
								configuration.clock())));
	}

	static <User> TokenExchangeService create(final TokenVerificationPolicy upstreamVerificationPolicy,
	                                          final String upstreamIssuerSecret,
	                                          final TokenIssuancePolicy issuancePolicy,
	                                          final String issuerSecret,
	                                          final TokenExchangeConfiguration<User> configuration)
	{
		Objects.requireNonNull(upstreamVerificationPolicy, "upstreamVerificationPolicy must not be null");
		Objects.requireNonNull(upstreamIssuerSecret, "upstreamIssuerSecret must not be null");

		return create(TokenVerifierFactory.hmac(upstreamVerificationPolicy, upstreamIssuerSecret),
				issuancePolicy,
				issuerSecret,
				configuration);
	}

	private HmacTokenExchangeServiceFactory()
	{
	}
}