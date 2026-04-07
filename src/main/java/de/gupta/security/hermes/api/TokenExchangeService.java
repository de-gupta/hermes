package de.gupta.security.hermes.api;

import de.gupta.security.hermes.domain.model.ExchangeResult;

public interface TokenExchangeService
{
	ExchangeResult exchange(final String externalToken);
}