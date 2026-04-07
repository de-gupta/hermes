package de.gupta.hermes.api;

import de.gupta.hermes.domain.model.ExchangeResult;

public interface TokenExchangeService
{
	ExchangeResult exchange(final String externalToken);
}