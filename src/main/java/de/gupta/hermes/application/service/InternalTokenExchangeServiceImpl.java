package de.gupta.hermes.application.service;

import de.gupta.commons.security.api.TokenVerifier;
import de.gupta.commons.security.domain.model.NormalizedToken;
import de.gupta.commons.security.domain.model.VerificationFailure;
import de.gupta.commons.security.domain.model.VerificationResult;
import de.gupta.commons.security.domain.model.VerificationSuccess;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import de.gupta.hermes.api.TokenExchangeConfiguration;
import de.gupta.hermes.api.TokenIssuancePolicy;
import de.gupta.hermes.domain.model.*;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

final class InternalTokenExchangeServiceImpl<User> implements InternalTokenExchangeService
{
	private final TokenVerifier upstreamTokenVerifier;
	private final TokenIssuancePolicy issuancePolicy;
	private final byte[] issuerSecret;
	private final TokenExchangeConfiguration<User> configuration;

	static <User> InternalTokenExchangeService create(final TokenVerifier upstreamTokenVerifier,
	                                                  final TokenIssuancePolicy issuancePolicy,
	                                                  final String issuerSecret,
	                                                  final TokenExchangeConfiguration<User> configuration)
	{
		return new InternalTokenExchangeServiceImpl<>(Objects.requireNonNull(upstreamTokenVerifier,
				"upstreamTokenVerifier must not be null"),
				Objects.requireNonNull(issuancePolicy, "issuancePolicy must not be null"),
				Objects.requireNonNull(issuerSecret, "issuerSecret must not be null")
				       .getBytes(StandardCharsets.UTF_8),
				Objects.requireNonNull(configuration, "configuration must not be null"));
	}

	@Override
	public ExchangeResult exchange(final String externalToken, final Instant issuedAt)
	{
		final VerificationResult verificationResult = upstreamTokenVerifier.verify(externalToken);
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

		final Optional<User> user = resolveUser(externalIdentity.get());
		if (user.isEmpty())
		{
			return ExchangeFailure.of(ExchangeFailureReason.USER_NOT_FOUND, externalIdentity.get());
		}

		final Optional<String> subject = resolveSubject(user.get());
		if (subject.isEmpty())
		{
			return ExchangeFailure.of(ExchangeFailureReason.MISSING_LOCAL_SUBJECT);
		}

		return exchangeVerifiedUser(user.get(), subject.get(), upstreamToken, issuedAt);
	}

	private ExchangeResult exchangeVerifiedUser(final User user,
	                                            final String subject,
	                                            final NormalizedToken upstreamToken,
	                                            final Instant issuedAt)
	{
		final Set<String> roles = resolveRoles(user);
		final long version = resolveVersion(user);
		final Instant expiresAt = issuedAt.plus(issuancePolicy.timeToLive());
		final Optional<String> tokenId = createTokenId();
		final Map<String, Object> claims = buildClaims(user, upstreamToken, roles, version);

		return issueToken(subject, roles, version, issuedAt, expiresAt, tokenId, claims, upstreamToken);
	}

	private Optional<String> resolveExternalIdentity(final NormalizedToken upstreamToken)
	{
		if ("sub".equals(configuration.externalIdentityClaimName()))
		{
			return Optional.ofNullable(upstreamToken.subject());
		}
		return upstreamToken.stringClaim(configuration.externalIdentityClaimName());
	}

	private Optional<User> resolveUser(final String externalIdentity)
	{
		return configuration.userResolver().resolveUser(externalIdentity);
	}

	private Optional<String> resolveSubject(final User user)
	{
		return Optional.ofNullable(configuration.localSubjectResolver().resolveSubject(user))
		               .filter(StringSanitizationUtility::isNotBlank);
	}

	private Set<String> resolveRoles(final User user)
	{
		return new LinkedHashSet<>(configuration.roleResolver().fetchRoles(user));
	}

	private long resolveVersion(final User user)
	{
		return configuration.tokenVersionResolver().resolveVersion(user);
	}

	private Optional<String> createTokenId()
	{
		return issuancePolicy.includeTokenId()
				? Optional.of(UUID.randomUUID().toString())
				: Optional.empty();
	}

	private Map<String, Object> buildClaims(final User user,
	                                        final NormalizedToken upstreamToken,
	                                        final Set<String> roles,
	                                        final long version)
	{
		final Map<String, Object> claims = new LinkedHashMap<>();
		claims.putAll(configuration.customClaimEnricher().enrich(user, upstreamToken));
		claims.put(issuancePolicy.roleClaimName(), List.copyOf(roles));
		claims.put(issuancePolicy.versionClaimName(), version);
		issuancePolicy.upstreamIssuerClaimName()
		              .flatMap(claimName -> upstreamToken.issuer().map(issuer -> Map.entry(claimName, issuer)))
		              .ifPresent(entry -> claims.put(entry.getKey(), entry.getValue()));
		return claims;
	}

	private ExchangeResult issueToken(final String subject,
	                                  final Set<String> roles,
	                                  final long version,
	                                  final Instant issuedAt,
	                                  final Instant expiresAt,
	                                  final Optional<String> tokenId,
	                                  final Map<String, Object> claims,
	                                  final NormalizedToken upstreamToken)
	{
		try
		{
			final var builder = Jwts.builder()
			                        .claims(claims)
			                        .subject(subject)
			                        .issuer(issuancePolicy.issuer())
			                        .issuedAt(Date.from(issuedAt))
			                        .expiration(Date.from(expiresAt))
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
		catch (JwtException exception)
		{
			return ExchangeFailure.of(ExchangeFailureReason.ISSUANCE_FAILED, exception.getMessage());
		}
	}

	private InternalTokenExchangeServiceImpl(final TokenVerifier upstreamTokenVerifier,
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