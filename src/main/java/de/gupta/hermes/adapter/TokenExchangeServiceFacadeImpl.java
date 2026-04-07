package de.gupta.hermes.adapter;

import de.gupta.hermes.application.service.TokenExchangeRequest;
import de.gupta.hermes.application.service.TokenExchangeService;
import de.gupta.hermes.domain.model.ExchangeResult;

import java.time.Clock;

final class TokenExchangeServiceFacadeImpl implements TokenExchangeServiceFacade
{
	private final TokenExchangeService service;
	private final Clock clock;

	static TokenExchangeServiceFacade create(final TokenExchangeService service, final Clock clock)
	{
		return new TokenExchangeServiceFacadeImpl(service, clock);
	}

	@Override
	public ExchangeResult exchange(final String externalToken)
	{
		return service.exchange(TokenExchangeRequest.of(externalToken, clock.instant()));
	}

	private TokenExchangeServiceFacadeImpl(final TokenExchangeService service, final Clock clock)
	{
		this.service = service;
		this.clock = clock;
	}
}