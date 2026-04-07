package de.gupta.security.hermes.api;

import de.gupta.security.themis.domain.model.NormalizedToken;

import java.util.Map;

@FunctionalInterface
public interface CustomClaimEnricher<User>
{
	Map<String, ?> enrich(final User user, final NormalizedToken upstreamToken);

	static <User> CustomClaimEnricher<User> none()
	{
		return (_, _) -> Map.of();
	}
}