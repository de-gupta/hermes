package de.gupta.hermes.application.service;

import java.time.Instant;

public record TokenExchangeRequest(String externalToken, Instant issuedAt)
{
	public static TokenExchangeRequest of(final String externalToken, final Instant issuedAt)
	{
		return new TokenExchangeRequest(externalToken, issuedAt);
	}
}
