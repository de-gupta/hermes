package de.gupta.security.hermes.api;

import de.gupta.security.hermes.adapter.TokenExchangeController;
import de.gupta.security.hermes.adapter.TokenExchangeControllerFactory;
import de.gupta.security.hermes.adapter.TokenExchangeServiceFacadeFactory;
import de.gupta.security.hermes.application.service.InternalTokenExchangeServiceFactory;
import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.api.TokenVerifier;
import de.gupta.security.themis.api.TokenVerifierFactory;

import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public final class TokenExchangeServiceFactory
{
	public static <User> TokenExchangeService hmac(final TokenVerifier upstreamTokenVerifier,
	                                               final TokenIssuancePolicy issuancePolicy,
	                                               final String issuerSecret,
	                                               final TokenExchangeConfiguration<User> configuration)
	{
		Objects.requireNonNull(issuerSecret, "issuerSecret must not be null");
		return create(TokenExchangeControllerFactory.create(
				TokenExchangeServiceFacadeFactory.create(
						InternalTokenExchangeServiceFactory.create(upstreamTokenVerifier,
								issuancePolicy,
								issuerSecret,
								configuration),
						configuration.clock())));
	}

	public static <User> TokenExchangeService hmac(
			final TokenVerificationConfiguration upstreamVerificationConfiguration,
	                                               final String upstreamIssuerSecret,
	                                               final TokenIssuancePolicy issuancePolicy,
	                                               final String issuerSecret,
	                                               final TokenExchangeConfiguration<User> configuration)
	{
		return hmac(TokenVerifierFactory.hmac(upstreamVerificationConfiguration, upstreamIssuerSecret),
				issuancePolicy,
				issuerSecret,
				configuration);
	}

	public static <User> TokenExchangeService rsa(final TokenVerifier upstreamTokenVerifier,
	                                              final TokenIssuancePolicy issuancePolicy,
	                                              final RSAPrivateKey issuerPrivateKey,
	                                              final TokenExchangeConfiguration<User> configuration)
	{
		return create(upstreamTokenVerifier, issuancePolicy, issuerPrivateKey, configuration);
	}

	public static <User> TokenExchangeService rsa(
			final TokenVerificationConfiguration upstreamVerificationConfiguration,
	                                              final RSAPublicKey upstreamIssuerPublicKey,
	                                              final TokenIssuancePolicy issuancePolicy,
	                                              final RSAPrivateKey issuerPrivateKey,
	                                              final TokenExchangeConfiguration<User> configuration)
	{
		return rsa(TokenVerifierFactory.rsa(upstreamVerificationConfiguration, upstreamIssuerPublicKey),
				issuancePolicy,
				issuerPrivateKey,
				configuration);
	}

	public static <User> TokenExchangeService ec(final TokenVerifier upstreamTokenVerifier,
	                                             final TokenIssuancePolicy issuancePolicy,
	                                             final ECPrivateKey issuerPrivateKey,
	                                             final TokenExchangeConfiguration<User> configuration)
	{
		return create(upstreamTokenVerifier, issuancePolicy, issuerPrivateKey, configuration);
	}

	public static <User> TokenExchangeService ec(final TokenVerificationConfiguration upstreamVerificationConfiguration,
	                                             final ECPublicKey upstreamIssuerPublicKey,
	                                             final TokenIssuancePolicy issuancePolicy,
	                                             final ECPrivateKey issuerPrivateKey,
	                                             final TokenExchangeConfiguration<User> configuration)
	{
		return ec(TokenVerifierFactory.ec(upstreamVerificationConfiguration, upstreamIssuerPublicKey),
				issuancePolicy,
				issuerPrivateKey,
				configuration);
	}

	private static <User> TokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                                  final TokenIssuancePolicy issuancePolicy,
	                                                  final Key issuerSigningKey,
	                                                  final TokenExchangeConfiguration<User> configuration)
	{
		Objects.requireNonNull(upstreamTokenVerifier, "upstreamTokenVerifier must not be null");
		Objects.requireNonNull(issuancePolicy, "issuancePolicy must not be null");
		Objects.requireNonNull(issuerSigningKey, "issuerSigningKey must not be null");
		Objects.requireNonNull(configuration, "configuration must not be null");

		return create(TokenExchangeControllerFactory.create(
				TokenExchangeServiceFacadeFactory.create(
						InternalTokenExchangeServiceFactory.create(upstreamTokenVerifier,
								issuancePolicy,
								issuerSigningKey,
								configuration),
						configuration.clock())));
	}

	private static TokenExchangeService create(final TokenExchangeController controller)
	{
		return ConfiguredTokenExchangeService.create(controller);
	}

	private TokenExchangeServiceFactory()
	{
	}
}