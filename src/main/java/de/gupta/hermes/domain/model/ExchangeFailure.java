package de.gupta.hermes.domain.model;

import java.util.Optional;

public record ExchangeFailure(ExchangeFailureReason reason, Optional<String> details) implements ExchangeResult
{
	public static ExchangeFailure of(final ExchangeFailureReason reason)
	{
		return new ExchangeFailure(reason, Optional.empty());
	}

	public static ExchangeFailure of(final ExchangeFailureReason reason, final String details)
	{
		return new ExchangeFailure(reason, Optional.ofNullable(details));
	}
}