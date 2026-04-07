package de.gupta.security.hermes.application.service;

import de.gupta.security.hermes.domain.model.ExchangeResult;

import java.time.Instant;

public interface InternalTokenExchangeService
{
	ExchangeResult exchange(final String externalToken, final Instant issuedAt);
}