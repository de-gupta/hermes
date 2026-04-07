package de.gupta.hermes.adapter;

import de.gupta.hermes.domain.model.ExchangeResult;

public interface TokenExchangeServiceFacade
{
	ExchangeResult exchange(final String externalToken);
}
