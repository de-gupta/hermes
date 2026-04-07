package de.gupta.hermes;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

public final class HermesTestTokens
{
	public static final String UPSTREAM_SECRET = "0123456789abcdef0123456789abcdef";
	public static final String INTERNAL_SECRET = "fedcba9876543210fedcba9876543210";

	public static String upstreamTokenWithSubject(final String subject)
	{
		return Jwts.builder()
		           .subject(subject)
		           .issuer("https://supabase.example")
		           .issuedAt(Date.from(Instant.parse("2026-04-08T10:15:30Z")))
		           .expiration(Date.from(Instant.parse("2026-04-08T11:15:30Z")))
		           .claim("email", subject + "@example.com")
		           .signWith(Keys.hmacShaKeyFor(UPSTREAM_SECRET.getBytes(StandardCharsets.UTF_8)))
		           .compact();
	}

	public static String upstreamTokenWithEmail(final String subject, final String email)
	{
		return Jwts.builder()
		           .subject(subject)
		           .issuer("https://supabase.example")
		           .issuedAt(Date.from(Instant.parse("2026-04-08T10:15:30Z")))
		           .expiration(Date.from(Instant.parse("2026-04-08T11:15:30Z")))
		           .claim("email", email)
		           .signWith(Keys.hmacShaKeyFor(UPSTREAM_SECRET.getBytes(StandardCharsets.UTF_8)))
		           .compact();
	}

	public static String upstreamTokenWithoutClaim(final String subject)
	{
		return Jwts.builder()
		           .subject(subject)
		           .issuer("https://supabase.example")
		           .issuedAt(Date.from(Instant.parse("2026-04-08T10:15:30Z")))
		           .expiration(Date.from(Instant.parse("2026-04-08T11:15:30Z")))
		           .signWith(Keys.hmacShaKeyFor(UPSTREAM_SECRET.getBytes(StandardCharsets.UTF_8)))
		           .compact();
	}

	public static Map<String, Object> parseInternalClaims(final String token)
	{
		return Jwts.parser()
		           .verifyWith(Keys.hmacShaKeyFor(INTERNAL_SECRET.getBytes(StandardCharsets.UTF_8)))
		           .build()
		           .parseSignedClaims(token)
		           .getPayload();
	}

	@SuppressWarnings("unchecked")
	public static List<String> rolesFromClaims(final Map<String, Object> claims)
	{
		return (List<String>) claims.get("roles");
	}

	private HermesTestTokens()
	{
	}
}