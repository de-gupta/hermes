package de.gupta.hermes;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

public final class HermesTestTokens
{
	public static final String UPSTREAM_SECRET = "0123456789abcdef0123456789abcdef";
	public static final String INTERNAL_SECRET = "fedcba9876543210fedcba9876543210";

	private static final KeyPair UPSTREAM_RSA_KEY_PAIR = newRsaKeyPair();
	public static final RSAPrivateKey UPSTREAM_RSA_PRIVATE_KEY = (RSAPrivateKey) UPSTREAM_RSA_KEY_PAIR.getPrivate();
	public static final RSAPublicKey UPSTREAM_RSA_PUBLIC_KEY = (RSAPublicKey) UPSTREAM_RSA_KEY_PAIR.getPublic();
	private static final KeyPair INTERNAL_RSA_KEY_PAIR = newRsaKeyPair();
	public static final RSAPrivateKey INTERNAL_RSA_PRIVATE_KEY = (RSAPrivateKey) INTERNAL_RSA_KEY_PAIR.getPrivate();
	public static final RSAPublicKey INTERNAL_RSA_PUBLIC_KEY = (RSAPublicKey) INTERNAL_RSA_KEY_PAIR.getPublic();
	private static final KeyPair UPSTREAM_EC_KEY_PAIR = newEcKeyPair();
	public static final ECPrivateKey UPSTREAM_EC_PRIVATE_KEY = (ECPrivateKey) UPSTREAM_EC_KEY_PAIR.getPrivate();
	public static final ECPublicKey UPSTREAM_EC_PUBLIC_KEY = (ECPublicKey) UPSTREAM_EC_KEY_PAIR.getPublic();
	private static final KeyPair INTERNAL_EC_KEY_PAIR = newEcKeyPair();
	public static final ECPrivateKey INTERNAL_EC_PRIVATE_KEY = (ECPrivateKey) INTERNAL_EC_KEY_PAIR.getPrivate();
	public static final ECPublicKey INTERNAL_EC_PUBLIC_KEY = (ECPublicKey) INTERNAL_EC_KEY_PAIR.getPublic();

	public static String upstreamTokenWithSubject(final String subject)
	{
		return upstreamHmacTokenWithSubject(subject);
	}

	public static String upstreamTokenWithEmail(final String subject, final String email)
	{
		return upstreamHmacTokenWithEmail(subject, email);
	}

	public static String upstreamTokenWithoutClaim(final String subject)
	{
		return upstreamHmacTokenWithoutClaim(subject);
	}

	public static String upstreamHmacTokenWithSubject(final String subject)
	{
		return buildUpstreamToken(subject, subject + "@example.com", hmacKey(UPSTREAM_SECRET));
	}

	public static String upstreamHmacTokenWithEmail(final String subject, final String email)
	{
		return buildUpstreamToken(subject, email, hmacKey(UPSTREAM_SECRET));
	}

	public static String upstreamHmacTokenWithoutClaim(final String subject)
	{
		return buildUpstreamTokenWithoutEmail(subject, hmacKey(UPSTREAM_SECRET));
	}

	public static String upstreamRsaTokenWithSubject(final String subject)
	{
		return buildUpstreamToken(subject, subject + "@example.com", UPSTREAM_RSA_PRIVATE_KEY);
	}

	public static String upstreamEcTokenWithSubject(final String subject)
	{
		return buildUpstreamToken(subject, subject + "@example.com", UPSTREAM_EC_PRIVATE_KEY);
	}

	public static Map<String, Object> parseInternalClaims(final String token, final Clock clock)
	{
		return parseInternalHmacClaims(token, clock);
	}

	public static Map<String, Object> parseInternalHmacClaims(final String token, final Clock clock)
	{
		return Jwts.parser()
		           .clock(() -> Date.from(clock.instant()))
		           .verifyWith(hmacKey(INTERNAL_SECRET))
		           .build()
		           .parseSignedClaims(token)
		           .getPayload();
	}

	public static Map<String, Object> parseInternalRsaClaims(final String token, final Clock clock)
	{
		return parseSignedClaims(token, INTERNAL_RSA_PUBLIC_KEY, clock);
	}

	public static Map<String, Object> parseInternalEcClaims(final String token, final Clock clock)
	{
		return parseSignedClaims(token, INTERNAL_EC_PUBLIC_KEY, clock);
	}

	@SuppressWarnings("unchecked")
	public static List<String> rolesFromClaims(final Map<String, Object> claims)
	{
		return (List<String>) claims.get("roles");
	}

	private static String buildUpstreamToken(final String subject, final String email, final Key signingKey)
	{
		final Instant now = Instant.now();
		return Jwts.builder()
		           .subject(subject)
		           .issuer("https://supabase.example")
		           .issuedAt(Date.from(now.minusSeconds(60)))
		           .expiration(Date.from(now.plusSeconds(3600)))
		           .claim("email", email)
		           .signWith(signingKey)
		           .compact();
	}

	private static String buildUpstreamTokenWithoutEmail(final String subject, final Key signingKey)
	{
		final Instant now = Instant.now();
		return Jwts.builder()
		           .subject(subject)
		           .issuer("https://supabase.example")
		           .issuedAt(Date.from(now.minusSeconds(60)))
		           .expiration(Date.from(now.plusSeconds(3600)))
		           .signWith(signingKey)
		           .compact();
	}

	private static Map<String, Object> parseSignedClaims(final String token,
	                                                     final PublicKey verificationKey,
	                                                     final Clock clock)
	{
		return Jwts.parser()
		           .clock(() -> Date.from(clock.instant()))
		           .verifyWith(verificationKey)
		           .build()
		           .parseSignedClaims(token)
		           .getPayload();
	}

	private static SecretKey hmacKey(final String secret)
	{
		return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
	}

	private static KeyPair newRsaKeyPair()
	{
		try
		{
			final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			return generator.generateKeyPair();
		}
		catch (Exception exception)
		{
			throw new IllegalStateException("Could not generate RSA test key pair", exception);
		}
	}

	private static KeyPair newEcKeyPair()
	{
		try
		{
			final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			return generator.generateKeyPair();
		}
		catch (Exception exception)
		{
			throw new IllegalStateException("Could not generate EC test key pair", exception);
		}
	}

	private HermesTestTokens()
	{
	}
}
