package de.gupta.security.hermes.application.service;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import de.gupta.security.hermes.api.TokenExchangeConfiguration;
import de.gupta.security.hermes.api.TokenIssuancePolicy;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailureReason;
import de.gupta.security.hermes.domain.model.ExchangeResult;
import de.gupta.security.themis.api.TokenVerifier;
import de.gupta.security.themis.domain.model.NormalizedToken;
import de.gupta.security.themis.domain.model.VerificationFailure;
import de.gupta.security.themis.domain.model.VerificationSuccess;

import java.security.Key;
import java.time.Instant;
import java.util.Optional;

final class InternalTokenExchangeServiceImpl<User> implements InternalTokenExchangeService
{
	private final TokenVerifier upstreamTokenVerifier;
	private final TokenExchangeConfiguration<User> configuration;
	private final InternalTokenMintingService<User> tokenMintingService;

	static <User> InternalTokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                                  final TokenIssuancePolicy issuancePolicy,
	                                                  final Key issuerSigningKey,
	                                                  final TokenExchangeConfiguration<User> configuration)
	{
		return new InternalTokenExchangeServiceImpl<>(
				upstreamTokenVerifier, configuration,
				InternalTokenMintingService.create(issuancePolicy,
						issuerSigningKey, configuration));
	}

	@Override
	public ExchangeResult exchange(final String externalToken, final Instant issuedAt)
	{
		return Unfolding.beckon(upstreamTokenVerifier.verify(externalToken))
		                .coronate(result -> result instanceof VerificationFailure failure
								? ExchangeFailure.of(ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED,
								failure.reason().name())
								: exchangeTrustedUpstreamToken(((VerificationSuccess) result).token(), issuedAt));
	}

	private ExchangeResult exchangeTrustedUpstreamToken(final NormalizedToken upstreamToken, final Instant issuedAt)
	{
		return Unfolding.augur(configuration.resolveExternalIdentity(upstreamToken))
		                .metamorphose(externalIdentity -> new ExternalIdentityContext(upstreamToken, externalIdentity,
								issuedAt))
		                .metamorphose(this::exchangeWithExternalIdentity)
		                .ordain(() -> ExchangeFailure.of(ExchangeFailureReason.MISSING_EXTERNAL_IDENTITY,
								configuration.externalIdentityClaimName()));
	}

	private ExchangeResult exchangeWithExternalIdentity(final ExternalIdentityContext externalIdentityContext)
	{
		return Unfolding.augur(resolveUser(externalIdentityContext.externalIdentity()))
		                .metamorphose(user -> new LocalUserContext<>(externalIdentityContext.upstreamToken(),
								externalIdentityContext.externalIdentity(),
								user,
								externalIdentityContext.issuedAt()))
		                .metamorphose(this::exchangeWithLocalUser)
		                .ordain(() -> ExchangeFailure.of(ExchangeFailureReason.USER_NOT_FOUND,
								externalIdentityContext.externalIdentity()));
	}

	private ExchangeResult exchangeWithLocalUser(final LocalUserContext<User> localUserContext)
	{
		return Unfolding.augur(resolveLocalSubject(localUserContext.user()))
		                .metamorphose(localSubject -> new LocalSubjectContext<>(localUserContext.upstreamToken(),
								localUserContext.user(),
								localSubject,
								localUserContext.issuedAt()))
		                .metamorphose(this::mintInternalToken)
		                .ordain(() -> ExchangeFailure.of(ExchangeFailureReason.MISSING_LOCAL_SUBJECT));
	}

	private ExchangeResult mintInternalToken(final LocalSubjectContext<User> localSubjectContext)
	{
		return tokenMintingService.mint(localSubjectContext.user(),
				localSubjectContext.localSubject(),
				localSubjectContext.upstreamToken(),
				localSubjectContext.issuedAt());
	}

	private Optional<User> resolveUser(final String externalIdentity)
	{
		return configuration.userResolver().resolveUser(externalIdentity);
	}

	private Optional<String> resolveLocalSubject(final User user)
	{
		return Optional.ofNullable(configuration.localSubjectResolver().resolveSubject(user))
		               .filter(StringSanitizationUtility::isNotBlank);
	}

	private InternalTokenExchangeServiceImpl(final TokenVerifier upstreamTokenVerifier,
	                                         final TokenExchangeConfiguration<User> configuration,
	                                         final InternalTokenMintingService<User> tokenMintingService)
	{
		this.upstreamTokenVerifier = upstreamTokenVerifier;
		this.configuration = configuration;
		this.tokenMintingService = tokenMintingService;
	}

	private record ExternalIdentityContext(NormalizedToken upstreamToken, String externalIdentity, Instant issuedAt)
	{
	}

	private record LocalUserContext<T>(NormalizedToken upstreamToken, String externalIdentity, T user, Instant issuedAt)
	{
	}

	private record LocalSubjectContext<T>(NormalizedToken upstreamToken, T user, String localSubject, Instant issuedAt)
	{
	}
}