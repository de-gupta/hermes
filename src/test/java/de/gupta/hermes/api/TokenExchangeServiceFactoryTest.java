package de.gupta.hermes.api;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.hermes.HermesTestTokens;
import de.gupta.security.hermes.api.*;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailureReason;
import de.gupta.security.hermes.domain.model.ExchangeResult;
import de.gupta.security.hermes.domain.model.ExchangeSuccess;
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
				TokenIssuancePolicy.of("Hermes", Set.of("internal-service"), Duration.ofMinutes(30)),
				HermesTestTokens.INTERNAL_SECRET,
				TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("local-42", externalId)),
						TestUser::id,
						_ -> Set.of("ROLE_ADMIN", "ROLE_USER"),
						_ -> 7L,
						(_, _) -> Map.of("tenant", "acme"),
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
		assertThat(claims.get("iss")).isEqualTo("Hermes");
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
				TokenIssuancePolicy.of("Hermes", Set.of(), Duration.ofMinutes(30)),
				HermesTestTokens.INTERNAL_SECRET,
				TokenExchangeConfiguration.of(_ -> Optional.empty(),
						TestUser::id,
						_ -> Set.of(),
						_ -> 1L,
						CustomClaimEnricher.none(),
						FIXED_CLOCK));

		final ExchangeResult result = service.exchange(HermesTestTokens.upstreamTokenWithSubject("missing-user"));

		assertThat(result).isInstanceOf(ExchangeFailure.class);
		assertThat(((ExchangeFailure) result).reason()).isEqualTo(ExchangeFailureReason.USER_NOT_FOUND);
	}

	@Test
	void shouldRejectBlankExternalTokenAtControllerBoundary()
	{
		final TokenExchangeService service = TokenExchangeServiceFactory.hmac(
				TokenVerificationPolicy.of(Duration.ZERO, true),
				HermesTestTokens.UPSTREAM_SECRET,
				TokenIssuancePolicy.of("Hermes", Set.of(), Duration.ofMinutes(30)),
				HermesTestTokens.INTERNAL_SECRET,
				TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("local-42", externalId)),
						TestUser::id,
						_ -> Set.of(),
						_ -> 1L,
						CustomClaimEnricher.none(),
						FIXED_CLOCK));

		final ExchangeResult result = service.exchange(" ");

		assertThat(result).isInstanceOf(ExchangeFailure.class);
		assertThat(((ExchangeFailure) result).reason()).isEqualTo(ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED);
		assertThat(((ExchangeFailure) result).details()).contains("externalToken must not be blank");
	}

	private record TestUser(String id, String externalId)
	{
	}
}