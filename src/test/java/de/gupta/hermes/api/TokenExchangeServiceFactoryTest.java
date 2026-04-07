package de.gupta.hermes.api;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.hermes.HermesTestTokens;
import de.gupta.hermes.domain.model.ExchangeFailure;
import de.gupta.hermes.domain.model.ExchangeFailureReason;
import de.gupta.hermes.domain.model.ExchangeResult;
import de.gupta.hermes.domain.model.ExchangeSuccess;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

final class TokenExchangeServiceFactoryTest
{
	private static final Clock FIXED_CLOCK =
			Clock.fixed(Instant.parse("2026-04-08T10:15:30Z"), ZoneOffset.UTC);

	@Test
	void shouldExchangeVerifiedUpstreamTokenIntoInternalToken()
	{
		final TokenExchangeService service = TokenExchangeServiceFactory.hmac(
				TokenVerificationPolicy.of(Duration.ZERO, true),
				HermesTestTokens.UPSTREAM_SECRET,
				TokenIssuancePolicy.of("hermes", Set.of("internal-service"), Duration.ofMinutes(30)),
				HermesTestTokens.INTERNAL_SECRET,
				TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("local-42", externalId)),
						TestUser::id,
						user -> Set.of("ROLE_ADMIN", "ROLE_USER"),
						user -> 7L,
						(user, upstreamToken) -> Map.of("tenant", "acme"),
						FIXED_CLOCK));

		final ExchangeResult result = service.exchange(HermesTestTokens.upstreamTokenWithSubject("external-123"));

		assertThat(result).isInstanceOf(ExchangeSuccess.class);
		final ExchangeSuccess success = (ExchangeSuccess) result;
		assertThat(success.token().subject()).isEqualTo("local-42");
		assertThat(success.token().roles()).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
		assertThat(success.token().version()).isEqualTo(7L);
		assertThat(success.token().upstreamIssuer()).contains("https://supabase.example");
		assertThat(success.token().tokenId()).isPresent();

		final Map<String, Object> claims = HermesTestTokens.parseInternalClaims(success.token().token());
		assertThat(claims.get("sub")).isEqualTo("local-42");
		assertThat(claims.get("iss")).isEqualTo("hermes");
		assertThat(HermesTestTokens.rolesFromClaims(claims)).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
		assertThat(claims.get("ver")).isEqualTo(7);
		assertThat(claims.get("tenant")).isEqualTo("acme");
		assertThat(claims.get("upstream_iss")).isEqualTo("https://supabase.example");
	}

	@Test
	void shouldReturnFailureWhenNoLocalUserCanBeResolved()
	{
		final TokenExchangeService service = TokenExchangeServiceFactory.hmac(
				TokenVerificationPolicy.of(Duration.ZERO, true),
				HermesTestTokens.UPSTREAM_SECRET,
				TokenIssuancePolicy.of("hermes", Set.of(), Duration.ofMinutes(30)),
				HermesTestTokens.INTERNAL_SECRET,
				TokenExchangeConfiguration.of(externalId -> Optional.empty(),
						TestUser::id,
						user -> Set.of(),
						user -> 1L,
						CustomClaimEnricher.none(),
						FIXED_CLOCK));

		final ExchangeResult result = service.exchange(HermesTestTokens.upstreamTokenWithSubject("missing-user"));

		assertThat(result).isInstanceOf(ExchangeFailure.class);
		assertThat(((ExchangeFailure) result).reason()).isEqualTo(ExchangeFailureReason.USER_NOT_FOUND);
	}

	private record TestUser(String id, String externalId)
	{
	}
}
