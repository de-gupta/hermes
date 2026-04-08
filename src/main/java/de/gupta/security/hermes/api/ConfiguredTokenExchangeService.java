package de.gupta.security.hermes.api;

import de.gupta.security.hermes.adapter.TokenExchangeController;
import de.gupta.security.hermes.domain.model.ExchangeResult;

final class ConfiguredTokenExchangeService implements TokenExchangeService
{
	private final TokenExchangeController controller;

	static TokenExchangeService create(final TokenExchangeController controller)
	{
		return new ConfiguredTokenExchangeService(controller);
	}

	@Override
	public ExchangeResult exchange(final String externalToken)
	{
		return controller.exchange(externalToken);
	}

	private ConfiguredTokenExchangeService(final TokenExchangeController controller)
	{
		this.controller = controller;
	}
}