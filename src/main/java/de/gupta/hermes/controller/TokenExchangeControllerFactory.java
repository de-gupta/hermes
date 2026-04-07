package de.gupta.hermes.controller;

import de.gupta.hermes.adapter.TokenExchangeServiceFacade;

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