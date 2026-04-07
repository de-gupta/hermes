package de.gupta.security.hermes.controller;

import de.gupta.security.hermes.adapter.TokenExchangeServiceFacade;

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