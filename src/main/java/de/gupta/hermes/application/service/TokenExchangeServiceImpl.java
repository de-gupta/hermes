package de.gupta.hermes.application.service;

import de.gupta.commons.security.api.TokenVerifier;
import de.gupta.commons.security.domain.model.NormalizedToken;
import de.gupta.commons.security.domain.model.VerificationFailure;
import de.gupta.commons.security.domain.model.VerificationResult;
import de.gupta.commons.security.domain.model.VerificationSuccess;
import de.gupta.hermes.api.TokenExchangeConfiguration;
import de.gupta.hermes.api.TokenIssuancePolicy;
import de.gupta.hermes.domain.model.ExchangeFailure;
import de.gupta.hermes.domain.model.ExchangeFailureReason;
import de.gupta.hermes.domain.model.ExchangeResult;
import de.gupta.hermes.domain.model.ExchangeSuccess;
import de.gupta.hermes.domain.model.IssuedToken;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

final class TokenExchangeServiceImpl<User> implements TokenExchangeService
{
	private final TokenVerifier upstreamTokenVerifier;
	private final TokenIssuancePolicy issuancePolicy;
	private final byte[] issuerSecret;
	private final TokenExchangeConfiguration<User> configuration;

	static <User> TokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                          final TokenIssuancePolicy issuancePolicy,
	                                          final String issuerSecret,
	                                          final TokenExchangeConfiguration<User> configuration)
	{
		return new TokenExchangeServiceImpl<>(upstreamTokenVerifier,
				issuancePolicy,
				issuerSecret.getBytes(StandardCharsets.UTF_8),
				configuration);
	}

	@Override
	public ExchangeResult exchange(final TokenExchangeRequest request)
	{
		try
		{
			final VerificationResult verificationResult = upstreamTokenVerifier.verify(request.externalToken());
			if (verificationResult instanceof VerificationFailure failure)
			{
				return ExchangeFailure.of(ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED, failure.reason().name());
			}

			final NormalizedToken upstreamToken = ((VerificationSuccess) verificationResult).token();
			final Optional<String> externalIdentity = resolveExternalIdentity(upstreamToken);
			if (externalIdentity.isEmpty())
			{
				return ExchangeFailure.of(ExchangeFailureReason.MISSING_EXTERNAL_IDENTITY,
						configuration.externalIdentityClaimName());
			}

			final Optional<User> user = configuration.userResolver().resolveUser(externalIdentity.get());
			if (user.isEmpty())
			{
				return ExchangeFailure.of(ExchangeFailureReason.USER_NOT_FOUND, externalIdentity.get());
			}

			final String subject = configuration.localSubjectResolver().resolveSubject(user.get());
			if (subject == null || subject.isBlank())
			{
				return ExchangeFailure.of(ExchangeFailureReason.MISSING_LOCAL_SUBJECT);
			}

			final Set<String> roles = new LinkedHashSet<>(configuration.roleResolver().fetchRoles(user.get()));
			final long version = configuration.tokenVersionResolver().resolveVersion(user.get());
			final Instant issuedAt = request.issuedAt();
			final Instant expiresAt = issuedAt.plus(issuancePolicy.timeToLive());
			final Optional<String> tokenId = issuancePolicy.includeTokenId()
					? Optional.of(UUID.randomUUID().toString())
					: Optional.empty();

			final Map<String, Object> claims = new LinkedHashMap<>();
			claims.putAll(configuration.customClaimEnricher().enrich(user.get(), upstreamToken));
			claims.put(issuancePolicy.roleClaimName(), List.copyOf(roles));
			claims.put(issuancePolicy.versionClaimName(), version);
			issuancePolicy.upstreamIssuerClaimName()
			              .flatMap(claimName -> upstreamToken.issuer().map(issuer -> Map.entry(claimName, issuer)))
			              .ifPresent(entry -> claims.put(entry.getKey(), entry.getValue()));

			final var builder = Jwts.builder()
			                        .subject(subject)
			                        .issuer(issuancePolicy.issuer())
			                        .issuedAt(Date.from(issuedAt))
			                        .expiration(Date.from(expiresAt))
			                        .claims(claims)
			                        .signWith(Keys.hmacShaKeyFor(issuerSecret));

			if (!issuancePolicy.audiences().isEmpty())
			{
				builder.audience().add(issuancePolicy.audiences()).and();
			}
			tokenId.ifPresent(builder::id);

			return ExchangeSuccess.of(IssuedToken.of(builder.compact(),
					subject,
					issuancePolicy.issuer(),
					issuancePolicy.audiences(),
					issuedAt,
					expiresAt,
					roles,
					version,
					tokenId,
					upstreamToken.issuer()));
		}
		catch (RuntimeException exception)
		{
			return ExchangeFailure.of(ExchangeFailureReason.ISSUANCE_FAILED, exception.getMessage());
		}
	}

	private Optional<String> resolveExternalIdentity(final NormalizedToken upstreamToken)
	{
		if ("sub".equals(configuration.externalIdentityClaimName()))
		{
			return Optional.ofNullable(upstreamToken.subject());
		}
		return upstreamToken.stringClaim(configuration.externalIdentityClaimName());
	}

	private TokenExchangeServiceImpl(final TokenVerifier upstreamTokenVerifier,
	                                 final TokenIssuancePolicy issuancePolicy,
	                                 final byte[] issuerSecret,
	                                 final TokenExchangeConfiguration<User> configuration)
	{
		this.upstreamTokenVerifier = upstreamTokenVerifier;
		this.issuancePolicy = issuancePolicy;
		this.issuerSecret = issuerSecret;
		this.configuration = configuration;
	}
}
