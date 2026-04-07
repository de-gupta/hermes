package de.gupta.security.hermes.controller;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import de.gupta.security.hermes.adapter.TokenExchangeServiceFacade;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailureReason;
import de.gupta.security.hermes.domain.model.ExchangeResult;

final class TokenExchangeControllerImpl implements TokenExchangeController
{
	private final TokenExchangeServiceFacade facade;

	static TokenExchangeController create(final TokenExchangeServiceFacade facade)
	{
		return new TokenExchangeControllerImpl(facade);
	}

	@Override
	public ExchangeResult exchange(final String externalToken)
	{
		try
		{
			Unfolding.beckon(externalToken)
			         .discern(StringSanitizationUtility::isNotBlank,
							 () -> new IllegalArgumentException("externalToken must not be blank"))
			         .summon();
			return facade.exchange(externalToken);
		}
		catch (IllegalArgumentException exception)
		{
			return ExchangeFailure.of(ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED, exception.getMessage());
		}
	}

	private TokenExchangeControllerImpl(final TokenExchangeServiceFacade facade)
	{
		this.facade = facade;
	}
}