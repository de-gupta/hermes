package de.gupta.security.hermes.controller;

import de.gupta.security.hermes.domain.model.ExchangeResult;

public interface TokenExchangeController
{
	ExchangeResult exchange(final String externalToken);
}