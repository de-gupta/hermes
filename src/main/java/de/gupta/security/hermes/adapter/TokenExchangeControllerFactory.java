package de.gupta.security.hermes.adapter;

public final class TokenExchangeControllerFactory
{
	public static TokenExchangeController create(final TokenExchangeServiceFacade facade)
	{
		return TokenExchangeControllerImpl.create(facade);
	}

	private TokenExchangeControllerFactory()
	{
	}
}