package de.gupta.security.hermes.api;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record TokenIssuancePolicy(String issuer, Set<String> audiences, Duration timeToLive, String roleClaimName,
                                  String versionClaimName, Optional<String> upstreamIssuerClaimName,
                                  boolean includeTokenId)
{
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

	public static TokenIssuancePolicy of(final String issuer, final Set<String> audiences, final Duration timeToLive)
	{
		return of(issuer, audiences, timeToLive, "roles", "ver", Optional.of("upstream_iss"), true);
	}

	public TokenIssuancePolicy
	{
		issuer = requireNonBlank(issuer, "issuer must not be blank");
		audiences = Set.copyOf(Objects.requireNonNull(audiences, "audiences must not be null"));
		timeToLive = Objects.requireNonNull(timeToLive, "timeToLive must not be null");
		if (timeToLive.isNegative() || timeToLive.isZero())
		{
			throw new IllegalArgumentException("timeToLive must be positive");
		}
		roleClaimName = requireNonBlank(roleClaimName, "roleClaimName must not be blank");
		versionClaimName = requireNonBlank(versionClaimName, "versionClaimName must not be blank");
		upstreamIssuerClaimName =
				Objects.requireNonNull(upstreamIssuerClaimName, "upstreamIssuerClaimName must not be null")
				       .map(value -> requireNonBlank(value,
							   "upstreamIssuerClaimName must not be blank"));
	}

	private static String requireNonBlank(final String value, final String message)
	{
		return Unfolding.beckon(value)
						 .discern(StringSanitizationUtility::isNotBlank,
						         () -> new IllegalArgumentException(message))
						.summon();
	}
}