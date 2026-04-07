package de.gupta.hermes.adapter;

import de.gupta.hermes.application.service.InternalTokenExchangeService;

import java.time.Clock;

public final class TokenExchangeServiceFacadeFactory
{
	public static TokenExchangeServiceFacade create(final InternalTokenExchangeService service, final Clock clock)
	{
		return TokenExchangeServiceFacadeImpl.create(service, clock);
	}

	private TokenExchangeServiceFacadeFactory()
	{
	}
}
