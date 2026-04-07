package de.gupta.hermes.controller;

import de.gupta.hermes.domain.model.ExchangeResult;

public interface TokenExchangeController
{
	ExchangeResult exchange(final String externalToken);
}