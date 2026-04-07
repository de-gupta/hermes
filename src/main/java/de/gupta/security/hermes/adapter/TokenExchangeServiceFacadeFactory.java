package de.gupta.security.hermes.adapter;

import de.gupta.security.hermes.application.service.InternalTokenExchangeService;

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