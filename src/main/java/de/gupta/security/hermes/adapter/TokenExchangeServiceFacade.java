package de.gupta.security.hermes.adapter;

import de.gupta.security.hermes.domain.model.ExchangeResult;

public interface TokenExchangeServiceFacade
{
	ExchangeResult exchange(final String externalToken);
}