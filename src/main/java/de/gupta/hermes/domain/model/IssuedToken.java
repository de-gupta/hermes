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
				Unfolding.beckon(subject)
								 .discern(StringSanitizationUtility::isNotBlank,
										 () -> new IllegalArgumentException("subject must not be blank"))
										 .summon(),
				Unfolding.beckon(issuer)
								 .discern(StringSanitizationUtility::isNotBlank,
										 () -> new IllegalArgumentException("issuer must not be blank"))
										 .summon(),
				Set.copyOf(Objects.requireNonNull(audiences, "audiences must not be null")),
				Objects.requireNonNull(issuedAt, "issuedAt must not be null"),
				Objects.requireNonNull(expiresAt, "expiresAt must not be null"),
				Set.copyOf(Objects.requireNonNull(roles, "roles must not be null")), version,
				// TOOD: no sanitization here. rather expose a factory method without these vars and call this one
				// with the default value
				tokenId == null ? Optional.empty() : tokenId,
				upstreamIssuer == null ? Optional.empty() : upstreamIssuer);
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

	private static String requireNonBlank(final String value, final String message)
	{
		Objects.requireNonNull(value, message);
		if (value.isBlank())
		{
			throw new IllegalArgumentException(message);
		}
		return value;
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