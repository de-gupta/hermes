package de.gupta.hermes.api;

import de.gupta.security.hermes.api.CustomClaimEnricher;
import de.gupta.security.hermes.api.TokenExchangeConfiguration;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

final class TokenExchangeConfigurationTest
{
	private static final Clock FIXED_CLOCK =
			Clock.fixed(Instant.parse("2026-04-08T10:15:30Z"), ZoneOffset.UTC);

	@Test
	void shouldDefaultToSubjectClaimAndSystemClock()
	{
		final TokenExchangeConfiguration<TestUser> configuration = TokenExchangeConfiguration.of(
				_ -> Optional.of(new TestUser("local-1")),
				TestUser::id,
				_ -> Set.of("ROLE_USER"));

		assertThat(configuration.externalIdentityClaimName()).isEqualTo("sub");
		assertThat(configuration.customClaimEnricher().enrich(new TestUser("local-1"), null)).isEmpty();
		assertThat(configuration.clock()).isNotNull();
	}

	@Test
	void shouldRejectBlankExternalIdentityClaimName()
	{
		assertThatThrownBy(() -> TokenExchangeConfiguration.of(" ",
				_ -> Optional.of(new TestUser("local-1")),
				TestUser::id,
				_ -> Set.of("ROLE_USER"),
				CustomClaimEnricher.none(),
				FIXED_CLOCK))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("externalIdentityClaimName must not be blank");
	}

	@Test
	void shouldUseProvidedClockAndCustomClaimEnricher()
	{
		final TokenExchangeConfiguration<TestUser> configuration = TokenExchangeConfiguration.of("email",
				_ -> Optional.of(new TestUser("local-1")),
				TestUser::id,
				_ -> Set.of("ROLE_USER"),
				(_, _) -> java.util.Map.of("tenant", "acme"),
				FIXED_CLOCK);

		assertThat(configuration.externalIdentityClaimName()).isEqualTo("email");
		assertThat(configuration.clock()).isEqualTo(FIXED_CLOCK);
		assertThat(configuration.customClaimEnricher().enrich(new TestUser("local-1"), null))
				.containsKey("tenant");
		assertThat(configuration.customClaimEnricher().enrich(new TestUser("local-1"), null).get("tenant"))
				.isEqualTo("acme");
	}

	private record TestUser(String id)
	{
	}
}
