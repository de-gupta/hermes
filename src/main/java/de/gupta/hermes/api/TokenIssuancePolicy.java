package de.gupta.hermes.api;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public final class TokenIssuancePolicy
{
	private final String issuer;
	private final Set<String> audiences;
	private final Duration timeToLive;
	private final String roleClaimName;
	private final String versionClaimName;
	private final Optional<String> upstreamIssuerClaimName;
	private final boolean includeTokenId;

	public static TokenIssuancePolicy of(final String issuer, final Set<String> audiences, final Duration timeToLive)
	{
		return of(issuer, audiences, timeToLive, "roles", "ver", Optional.of("upstream_iss"), true);
	}

	public static TokenIssuancePolicy of(final String issuer,
	                                     final Set<String> audiences,
	                                     final Duration timeToLive,
	                                     final String roleClaimName,
	                                     final String versionClaimName,
	                                     final Optional<String> upstreamIssuerClaimName,
	                                     final boolean includeTokenId)
	{
		final String normalizedIssuer = requireNonBlank(issuer, "issuer must not be blank");
		final Duration normalizedTtl = Objects.requireNonNull(timeToLive, "timeToLive must not be null");
		if (normalizedTtl.isNegative() || normalizedTtl.isZero())
		{
			throw new IllegalArgumentException("timeToLive must be positive");
		}
		final Set<String> normalizedAudiences = Set.copyOf(Objects.requireNonNull(audiences, "audiences must not be null"));
		final String normalizedRoleClaimName = requireNonBlank(roleClaimName, "roleClaimName must not be blank");
		final String normalizedVersionClaimName = requireNonBlank(versionClaimName, "versionClaimName must not be blank");
		// TODO: again no null check, rather expose separate method without those args and call this with default value
		final Optional<String> normalizedUpstreamIssuerClaimName = upstreamIssuerClaimName == null
				? Optional.of("upstream_iss")
				: upstreamIssuerClaimName.map(value -> requireNonBlank(value, "upstreamIssuerClaimName must not be blank"));

		return new TokenIssuancePolicy(normalizedIssuer,
				normalizedAudiences,
				normalizedTtl,
				normalizedRoleClaimName,
				normalizedVersionClaimName,
				normalizedUpstreamIssuerClaimName,
				includeTokenId);
	}

	public String issuer()
	{
		return issuer;
	}

	public Set<String> audiences()
	{
		return audiences;
	}

	public Duration timeToLive()
	{
		return timeToLive;
	}

	public String roleClaimName()
	{
		return roleClaimName;
	}

	public String versionClaimName()
	{
		return versionClaimName;
	}

	public Optional<String> upstreamIssuerClaimName()
	{
		return upstreamIssuerClaimName;
	}

	public boolean includeTokenId()
	{
		return includeTokenId;
	}

	@Override
	public boolean equals(final Object object)
	{
		if (this == object)
		{
			return true;
		}
		if (!(object instanceof TokenIssuancePolicy that))
		{
			return false;
		}
		return includeTokenId == that.includeTokenId
				&& Objects.equals(issuer, that.issuer)
				&& Objects.equals(audiences, that.audiences)
				&& Objects.equals(timeToLive, that.timeToLive)
				&& Objects.equals(roleClaimName, that.roleClaimName)
				&& Objects.equals(versionClaimName, that.versionClaimName)
				&& Objects.equals(upstreamIssuerClaimName, that.upstreamIssuerClaimName);
	}

	@Override
	public int hashCode()
	{
		return Objects.hash(issuer,
				audiences,
				timeToLive,
				roleClaimName,
				versionClaimName,
				upstreamIssuerClaimName,
				includeTokenId);
	}

	@Override
	public String toString()
	{
		return "TokenIssuancePolicy[issuer=%s, audiences=%s, timeToLive=%s, roleClaimName=%s, versionClaimName=%s, upstreamIssuerClaimName=%s, includeTokenId=%s]"
				.formatted(issuer,
						audiences,
						timeToLive,
						roleClaimName,
						versionClaimName,
						upstreamIssuerClaimName,
						includeTokenId);
	}

	private static String requireNonBlank(final String value, final String message)
	{
		Objects.requireNonNull(value, message);
		if (value.isBlank())
		{
			throw new IllegalArgumentException(message);
		}
		return value;
	}

	private TokenIssuancePolicy(final String issuer,
	                            final Set<String> audiences,
	                            final Duration timeToLive,
	                            final String roleClaimName,
	                            final String versionClaimName,
	                            final Optional<String> upstreamIssuerClaimName,
	                            final boolean includeTokenId)
	{
		this.issuer = issuer;
		this.audiences = audiences;
		this.timeToLive = timeToLive;
		this.roleClaimName = roleClaimName;
		this.versionClaimName = versionClaimName;
		this.upstreamIssuerClaimName = upstreamIssuerClaimName;
		this.includeTokenId = includeTokenId;
	}
}