package de.gupta.security.hermes.domain.model;

public sealed interface ExchangeResult permits ExchangeSuccess, ExchangeFailure
{
}