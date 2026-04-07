package de.gupta.hermes.api;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

// TODO: convert to final class witih private constructor and static factory method - validation should happen in static factory
public record TokenIssuancePolicy(String issuer, Set<String> audiences, Duration timeToLive, String roleClaimName,
                                  String versionClaimName, Optional<String> upstreamIssuerClaimName,
                                  boolean includeTokenId)
{
	public TokenIssuancePolicy
	{
		Objects.requireNonNull(issuer, "issuer must not be null");
		audiences = Set.copyOf(audiences);
		Objects.requireNonNull(timeToLive, "timeToLive must not be null");
		Objects.requireNonNull(roleClaimName, "roleClaimName must not be null");
		Objects.requireNonNull(versionClaimName, "versionClaimName must not be null");
		upstreamIssuerClaimName = upstreamIssuerClaimName == null ? Optional.of("upstream_iss") : upstreamIssuerClaimName;
	}

	public static TokenIssuancePolicy of(final String issuer, final Set<String> audiences, final Duration timeToLive)
	{
		return new TokenIssuancePolicy(issuer,
				audiences,
				timeToLive,
				"roles",
				"ver",
				Optional.of("upstream_iss"),
				true);
	}

	public static TokenIssuancePolicy of(final String issuer,
	                                     final Set<String> audiences,
	                                     final Duration timeToLive,
	                                     final String roleClaimName,
	                                     final String versionClaimName,
	                                     final Optional<String> upstreamIssuerClaimName,
	                                     final boolean includeTokenId)
	{
		return new TokenIssuancePolicy(issuer,
				audiences,
				timeToLive,
				roleClaimName,
				versionClaimName,
				upstreamIssuerClaimName,
				includeTokenId);
	}
}