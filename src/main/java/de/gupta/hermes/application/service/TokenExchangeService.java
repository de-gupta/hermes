package de.gupta.hermes.application.service;

import de.gupta.hermes.domain.model.ExchangeResult;

public interface TokenExchangeService
{
	ExchangeResult exchange(final TokenExchangeRequest request);
}