package de.gupta.hermes.adapter;

import de.gupta.hermes.application.service.InternalTokenExchangeService;
import de.gupta.hermes.domain.model.ExchangeResult;

import java.time.Clock;

// TODO: change back to inerface/impl/factory trio
public final class TokenExchangeServiceFacade
{
	// TODO: is ? really acceptable generic type? facade doen't need to know user type?
	private final InternalTokenExchangeService<?> service;
	private final Clock clock;

	public static TokenExchangeServiceFacade create(final InternalTokenExchangeService<?> service, final Clock clock)
	{
		return new TokenExchangeServiceFacade(service, clock);
	}

	public ExchangeResult exchange(final String externalToken)
	{
		return service.exchange(externalToken, clock.instant());
	}

	private TokenExchangeServiceFacade(final InternalTokenExchangeService<?> service, final Clock clock)
	{
		this.service = service;
		this.clock = clock;
	}
}