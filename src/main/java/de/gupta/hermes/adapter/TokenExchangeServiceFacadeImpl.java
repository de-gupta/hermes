package de.gupta.hermes.adapter;

import de.gupta.hermes.application.service.InternalTokenExchangeService;
import de.gupta.hermes.domain.model.ExchangeResult;

import java.time.Clock;

final class TokenExchangeServiceFacadeImpl implements TokenExchangeServiceFacade
{
	private final InternalTokenExchangeService service;
	private final Clock clock;

	static TokenExchangeServiceFacade create(final InternalTokenExchangeService service, final Clock clock)
	{
		return new TokenExchangeServiceFacadeImpl(service, clock);
	}

	@Override
	public ExchangeResult exchange(final String externalToken)
	{
		return service.exchange(externalToken, clock.instant());
	}

	private TokenExchangeServiceFacadeImpl(final InternalTokenExchangeService service, final Clock clock)
	{
		this.service = service;
		this.clock = clock;
	}
}
