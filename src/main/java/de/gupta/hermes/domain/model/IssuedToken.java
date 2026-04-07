package de.gupta.hermes.domain.model;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

// TODO: convert to final class witih private constructor and static factory method - defensive copy should happen in static factory
public record IssuedToken(String token, String subject, String issuer, Set<String> audiences, Instant issuedAt,
                          Instant expiresAt, Set<String> roles, long version, Optional<String> tokenId,
                          Optional<String> upstreamIssuer)
{
	public IssuedToken
	{
		audiences = Set.copyOf(audiences);
		roles = Set.copyOf(roles);
	}

	public static IssuedToken of(final String token,
	                             final String subject,
	                             final String issuer,
	                             final Set<String> audiences,
	                             final Instant issuedAt,
	                             final Instant expiresAt,
	                             final Set<String> roles,
	                             final long version,
	                             final Optional<String> tokenId,
	                             final Optional<String> upstreamIssuer)
	{
		return new IssuedToken(token,
				subject,
				issuer,
				audiences,
				issuedAt,
				expiresAt,
				roles,
				version,
				tokenId,
				upstreamIssuer);
	}
}