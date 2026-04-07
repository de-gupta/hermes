package de.gupta.hermes.controller;

import de.gupta.commons.utility.string.StringSanitizationUtility;
import de.gupta.hermes.adapter.TokenExchangeServiceFacade;
import de.gupta.hermes.domain.model.ExchangeFailure;
import de.gupta.hermes.domain.model.ExchangeFailureReason;
import de.gupta.hermes.domain.model.ExchangeResult;

// TODO: change back to inerface/impl/factory trio
public final class TokenExchangeController
{
	private final TokenExchangeServiceFacade facade;

	public static TokenExchangeController create(final TokenExchangeServiceFacade facade)
	{
		return new TokenExchangeController(facade);
	}

	public ExchangeResult exchange(final String externalToken)
	{
		// TODO: use rich methods from Unfolding here - discern/cleave/evolve etc. you'll find soemthing
		if (!StringSanitizationUtility.isNotBlank(externalToken))
		{
			return ExchangeFailure.of(ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED,
					"externalToken must not be blank");
		}
		return facade.exchange(externalToken);
	}

	private TokenExchangeController(final TokenExchangeServiceFacade facade)
	{
		this.facade = facade;
	}
}