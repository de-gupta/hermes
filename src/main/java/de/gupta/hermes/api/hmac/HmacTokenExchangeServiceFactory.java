package de.gupta.hermes.api.hmac;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.api.TokenVerifier;
import de.gupta.commons.security.api.TokenVerifierFactory;
import de.gupta.hermes.adapter.TokenExchangeServiceFacade;
import de.gupta.hermes.api.TokenExchangeConfiguration;
import de.gupta.hermes.api.TokenExchangeService;
import de.gupta.hermes.api.TokenIssuancePolicy;
import de.gupta.hermes.application.service.InternalTokenExchangeService;
import de.gupta.hermes.controller.TokenExchangeController;

import java.util.Objects;

public final class HmacTokenExchangeServiceFactory
{
	public static <User> TokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                                 final TokenIssuancePolicy issuancePolicy,
	                                                 final String issuerSecret,
	                                                 final TokenExchangeConfiguration<User> configuration)
	{
		Objects.requireNonNull(upstreamTokenVerifier, "upstreamTokenVerifier must not be null");
		Objects.requireNonNull(issuancePolicy, "issuancePolicy must not be null");
		Objects.requireNonNull(issuerSecret, "issuerSecret must not be null");
		Objects.requireNonNull(configuration, "configuration must not be null");

		return HmacTokenExchangeService.create(
				TokenExchangeController.create(
						TokenExchangeServiceFacade.create(
								InternalTokenExchangeService.create(upstreamTokenVerifier,
										issuancePolicy,
										issuerSecret,
										configuration),
								configuration.clock())));
	}

	public static <User> TokenExchangeService create(final TokenVerificationPolicy upstreamVerificationPolicy,
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