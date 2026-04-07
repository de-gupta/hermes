package de.gupta.hermes.api.hmac;

import de.gupta.hermes.api.TokenExchangeService;
import de.gupta.hermes.controller.TokenExchangeController;
import de.gupta.hermes.domain.model.ExchangeResult;

final class HmacTokenExchangeService implements TokenExchangeService
{
	private final TokenExchangeController controller;

	static TokenExchangeService create(final TokenExchangeController controller)
	{
		return new HmacTokenExchangeService(controller);
	}

	@Override
	public ExchangeResult exchange(final String externalToken)
	{
		return controller.exchange(externalToken);
	}

	private HmacTokenExchangeService(final TokenExchangeController controller)
	{
		this.controller = controller;
	}
}