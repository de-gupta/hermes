package de.gupta.hermes.controller;

import de.gupta.hermes.adapter.TokenExchangeServiceFacade;
import de.gupta.hermes.domain.model.ExchangeResult;

final class TokenExchangeControllerImpl implements TokenExchangeController
{
	private final TokenExchangeServiceFacade facade;

	static TokenExchangeController create(final TokenExchangeServiceFacade facade)
	{
		return new TokenExchangeControllerImpl(facade);
	}

	@Override
	public ExchangeResult exchange(final String externalToken)
	{
		return facade.exchange(externalToken);
	}

	private TokenExchangeControllerImpl(final TokenExchangeServiceFacade facade)
	{
		this.facade = facade;
	}
}