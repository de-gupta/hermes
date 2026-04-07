package de.gupta.hermes.application.service;

import de.gupta.hermes.domain.model.ExchangeResult;

import java.time.Instant;

public interface InternalTokenExchangeService
{
	ExchangeResult exchange(final String externalToken, final Instant issuedAt);
}
