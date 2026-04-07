package de.gupta.hermes.domain.model;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public final class IssuedToken
{
	private final String token;
	private final String subject;
	private final String issuer;
	private final Set<String> audiences;
	private final Instant issuedAt;
	private final Instant expiresAt;
	private final Set<String> roles;
	private final long version;
	private final Optional<String> tokenId;
	private final Optional<String> upstreamIssuer;

	public static IssuedToken of(final String token, final String subject, final String issuer,
	                             final Set<String> audiences, final Instant issuedAt, final Instant expiresAt,
	                             final Set<String> roles, final long version, final Optional<String> tokenId,
	                             final Optional<String> upstreamIssuer)
	{
		return new IssuedToken(Objects.requireNonNull(token, "token must not be null"),
				requireNonBlank(subject, "subject must not be blank"),
				requireNonBlank(issuer, "issuer must not be blank"),
				Set.copyOf(Objects.requireNonNull(audiences, "audiences must not be null")),
				Objects.requireNonNull(issuedAt, "issuedAt must not be null"),
				Objects.requireNonNull(expiresAt, "expiresAt must not be null"),
				Set.copyOf(Objects.requireNonNull(roles, "roles must not be null")), version,
				Objects.requireNonNull(tokenId, "tokenId must not be null"),
				Objects.requireNonNull(upstreamIssuer, "upstreamIssuer must not be null"));
	}

	public static IssuedToken of(final String token,
	                             final String subject,
	                             final String issuer,
	                             final Set<String> audiences,
	                             final Instant issuedAt,
	                             final Instant expiresAt,
	                             final Set<String> roles,
	                             final long version)
	{
		return of(token, subject, issuer, audiences, issuedAt, expiresAt, roles, version, Optional.empty(),
				Optional.empty());
	}

	public String token()
	{
		return token;
	}

	public String subject()
	{
		return subject;
	}

	public String issuer()
	{
		return issuer;
	}

	public Set<String> audiences()
	{
		return audiences;
	}

	public Instant issuedAt()
	{
		return issuedAt;
	}

	public Instant expiresAt()
	{
		return expiresAt;
	}

	public Set<String> roles()
	{
		return roles;
	}

	public long version()
	{
		return version;
	}

	public Optional<String> tokenId()
	{
		return tokenId;
	}

	public Optional<String> upstreamIssuer()
	{
		return upstreamIssuer;
	}

	@Override
	public boolean equals(final Object object)
	{
		if (this == object)
		{
			return true;
		}
		if (!(object instanceof IssuedToken that))
		{
			return false;
		}
		return version == that.version
				&& Objects.equals(token, that.token)
				&& Objects.equals(subject, that.subject)
				&& Objects.equals(issuer, that.issuer)
				&& Objects.equals(audiences, that.audiences)
				&& Objects.equals(issuedAt, that.issuedAt)
				&& Objects.equals(expiresAt, that.expiresAt)
				&& Objects.equals(roles, that.roles)
				&& Objects.equals(tokenId, that.tokenId)
				&& Objects.equals(upstreamIssuer, that.upstreamIssuer);
	}

	@Override
	public int hashCode()
	{
		return Objects.hash(token, subject, issuer, audiences, issuedAt, expiresAt, roles, version, tokenId,
				upstreamIssuer);
	}

	@Override
	public String toString()
	{
		return "IssuedToken[token=%s, subject=%s, issuer=%s, audiences=%s, issuedAt=%s, expiresAt=%s, roles=%s, version=%s, tokenId=%s, upstreamIssuer=%s]"
				.formatted(token,
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

	private static String requireNonBlank(final String value, final String message)
	{
		return Unfolding.beckon(value)
						 .discern(StringSanitizationUtility::isNotBlank,
						         () -> new IllegalArgumentException(message))
						 .summon();
	}

	private IssuedToken(final String token, final String subject, final String issuer, final Set<String> audiences,
	                    final Instant issuedAt, final Instant expiresAt, final Set<String> roles, final long version,
	                    final Optional<String> tokenId, final Optional<String> upstreamIssuer)
	{
		this.token = token;
		this.subject = subject;
		this.issuer = issuer;
		this.audiences = audiences;
		this.issuedAt = issuedAt;
		this.expiresAt = expiresAt;
		this.roles = roles;
		this.version = version;
		this.tokenId = tokenId;
		this.upstreamIssuer = upstreamIssuer;
	}
}
