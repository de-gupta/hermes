package de.gupta.security.hermes.domain.model;

public record ExchangeSuccess(IssuedToken token) implements ExchangeResult
{
	public static ExchangeSuccess of(final IssuedToken token)
	{
		return new ExchangeSuccess(token);
	}
}