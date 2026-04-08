package de.gupta.security.hermes.application.service;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.security.hermes.api.TokenExchangeConfiguration;
import de.gupta.security.hermes.api.TokenIssuancePolicy;
import de.gupta.security.hermes.domain.model.*;
import de.gupta.security.themis.domain.model.NormalizedToken;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;

final class InternalTokenMintingService<User>
{
	private final TokenIssuancePolicy issuancePolicy;
	private final Key issuerSigningKey;
	private final TokenExchangeConfiguration<User> configuration;

	static <User> InternalTokenMintingService<User> create(final TokenIssuancePolicy issuancePolicy,
	                                                       final Key issuerSigningKey,
	                                                       final TokenExchangeConfiguration<User> configuration)
	{
		return new InternalTokenMintingService<>(
				Objects.requireNonNull(issuancePolicy, "issuancePolicy must not be null"),
				Objects.requireNonNull(issuerSigningKey, "issuerSigningKey must not be null"),
				Objects.requireNonNull(configuration, "configuration must not be null"));
	}

	ExchangeResult mint(final User user,
	                    final String localSubject,
	                    final NormalizedToken upstreamToken,
	                    final Instant issuedAt)
	{
		final Set<String> roles = resolveRoles(user);
		final long version = resolveVersion(user);
		final Instant expiresAt = issuedAt.plus(issuancePolicy.timeToLive());
		final Optional<String> tokenId = createTokenId();
		final Map<String, Object> claims = buildClaims(user, upstreamToken, roles, version);

		return issueJwt(localSubject, roles, version, issuedAt, expiresAt, tokenId, claims, upstreamToken);
	}

	private Set<String> resolveRoles(final User user)
	{
		return new HashSet<>(configuration.roleResolver().fetchRoles(user));
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
		final SequencedCollection<Function<? super ClaimAssemblyContext<User>, ? extends Map<String, Object>>>
				claimFragments =
				new ArrayList<>();
		claimFragments.add(this::customClaims);
		claimFragments.add(this::roleClaims);
		claimFragments.add(this::versionClaims);
		claimFragments.add(this::upstreamIssuerClaims);

		return Unfolding.beckon(new ClaimAssemblyContext<>(user, upstreamToken, roles, version))
		                .convoke(claimFragments, fragments -> mergeClaimFragments(fragments))
		                .coronate(Function.identity());
	}

	private Map<String, Object> customClaims(final ClaimAssemblyContext<User> context)
	{
		return new HashMap<>(configuration.customClaimEnricher().enrich(context.user(), context.upstreamToken()));
	}

	private Map<String, Object> roleClaims(final ClaimAssemblyContext<User> context)
	{
		return Map.of(issuancePolicy.roleClaimName(), context.roles().stream().sorted().toList());
	}

	private Map<String, Object> versionClaims(final ClaimAssemblyContext<User> context)
	{
		return Map.of(issuancePolicy.versionClaimName(), context.version());
	}

	private Map<String, Object> upstreamIssuerClaims(final ClaimAssemblyContext<User> context)
	{
		return issuancePolicy.upstreamIssuerClaimName()
		                     .flatMap(claimName -> context.upstreamToken()
		                                                  .issuer()
		                                                  .map(issuer -> Map.of(claimName, (Object) issuer)))
		                     .orElseGet(Map::of);
	}

	private Map<String, Object> mergeClaimFragments(final SequencedCollection<? extends Map<String, Object>> fragments)
	{
		final Map<String, Object> mergedClaims = new LinkedHashMap<>();
		fragments.forEach(mergedClaims::putAll);
		return mergedClaims;
	}

	private ExchangeResult issueJwt(final String localSubject,
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
			                        .subject(localSubject)
			                        .issuer(issuancePolicy.issuer())
			                        .issuedAt(Date.from(issuedAt))
			                        .expiration(Date.from(expiresAt))
			                        .signWith(issuerSigningKey);

			if (!issuancePolicy.audiences().isEmpty())
			{
				builder.audience().add(issuancePolicy.audiences()).and();
			}
			tokenId.ifPresent(builder::id);

			return ExchangeSuccess.of(IssuedToken.of(builder.compact(),
					localSubject,
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

	private InternalTokenMintingService(final TokenIssuancePolicy issuancePolicy,
	                                    final Key issuerSigningKey,
	                                    final TokenExchangeConfiguration<User> configuration)
	{
		this.issuancePolicy = issuancePolicy;
		this.issuerSigningKey = issuerSigningKey;
		this.configuration = configuration;
	}

	private record ClaimAssemblyContext<T>(T user, NormalizedToken upstreamToken, Set<String> roles, long version)
	{
	}
}
