package de.gupta.hermes.domain.model;

public sealed interface ExchangeResult permits ExchangeSuccess, ExchangeFailure
{
}