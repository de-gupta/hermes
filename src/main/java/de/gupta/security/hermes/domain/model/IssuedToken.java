package de.gupta.security.hermes.domain.model;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record IssuedToken(String token, String subject, String issuer, Set<String> audiences, Instant issuedAt,
                          Instant expiresAt, Set<String> roles, long version, Optional<String> tokenId,
                          Optional<String> upstreamIssuer)
{
	public static IssuedToken of(final String token, final String subject, final String issuer,
	                             final Set<String> audiences, final Instant issuedAt, final Instant expiresAt,
	                             final Set<String> roles, final long version, final Optional<String> tokenId,
	                             final Optional<String> upstreamIssuer)
	{
		return new IssuedToken(token, subject, issuer, audiences, issuedAt, expiresAt, roles, version, tokenId,
				upstreamIssuer);
	}

	public static IssuedToken of(final String token, final String subject, final String issuer,
	                             final Set<String> audiences, final Instant issuedAt, final Instant expiresAt,
	                             final Set<String> roles, final long version)
	{
		return of(token, subject, issuer, audiences, issuedAt, expiresAt, roles, version, Optional.empty(),
				Optional.empty());
	}

	public IssuedToken
	{
		token = Objects.requireNonNull(token, "token must not be null");
		subject = requireNonBlank(subject, "subject must not be blank");
		issuer = requireNonBlank(issuer, "issuer must not be blank");
		audiences = Set.copyOf(Objects.requireNonNull(audiences, "audiences must not be null"));
		issuedAt = Objects.requireNonNull(issuedAt, "issuedAt must not be null");
		expiresAt = Objects.requireNonNull(expiresAt, "expiresAt must not be null");
		roles = Set.copyOf(Objects.requireNonNull(roles, "roles must not be null"));
		tokenId = Objects.requireNonNull(tokenId, "tokenId must not be null");
		upstreamIssuer = Objects.requireNonNull(upstreamIssuer, "upstreamIssuer must not be null");
	}

	private static String requireNonBlank(final String value, final String message)
	{
		return Unfolding.beckon(value)
		                .discern(StringSanitizationUtility::isNotBlank, () -> new IllegalArgumentException(message))
		                .summon();
	}
}