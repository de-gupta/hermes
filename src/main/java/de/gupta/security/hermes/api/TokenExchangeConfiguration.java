package de.gupta.security.hermes.api;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import de.gupta.security.themis.domain.model.NormalizedToken;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;

public record TokenExchangeConfiguration<User>(String externalIdentityClaimName,
                                               UserResolver<String, User> userResolver,
                                               LocalSubjectResolver<User> localSubjectResolver,
                                               RoleResolver<User> roleResolver,
                                               TokenVersionResolver<User> tokenVersionResolver,
                                               CustomClaimEnricher<User> customClaimEnricher,
                                               Clock clock)
{
	public Optional<String> resolveExternalIdentity(final NormalizedToken upstreamToken)
	{
		return "sub".equals(externalIdentityClaimName)
				? Optional.ofNullable(upstreamToken.subject())
				: upstreamToken.property(externalIdentityClaimName);
	}

	public static <User> TokenExchangeConfiguration<User> of(final String externalIdentityClaimName,
	                                                         final UserResolver<String, User> userResolver,
	                                                         final LocalSubjectResolver<User> localSubjectResolver,
	                                                         final RoleResolver<User> roleResolver,
	                                                         final TokenVersionResolver<User> tokenVersionResolver,
	                                                         final CustomClaimEnricher<User> customClaimEnricher,
	                                                         final Clock clock)
	{
		return new TokenExchangeConfiguration<>(externalIdentityClaimName,
				userResolver,
				localSubjectResolver,
				roleResolver,
				tokenVersionResolver,
				customClaimEnricher,
				clock);
	}

	public static <User> TokenExchangeConfiguration<User> of(final UserResolver<String, User> userResolver,
	                                                         final LocalSubjectResolver<User> localSubjectResolver,
	                                                         final RoleResolver<User> roleResolver,
	                                                         final TokenVersionResolver<User> tokenVersionResolver)
	{
		return of("sub",
				userResolver,
				localSubjectResolver,
				roleResolver,
				tokenVersionResolver,
				CustomClaimEnricher.none(),
				Clock.systemUTC());
	}

	public static <User> TokenExchangeConfiguration<User> of(final UserResolver<String, User> userResolver,
	                                                         final LocalSubjectResolver<User> localSubjectResolver,
	                                                         final RoleResolver<User> roleResolver,
	                                                         final TokenVersionResolver<User> tokenVersionResolver,
	                                                         final CustomClaimEnricher<User> customClaimEnricher,
	                                                         final Clock clock)
	{
		return of("sub",
				userResolver,
				localSubjectResolver,
				roleResolver,
				tokenVersionResolver,
				customClaimEnricher,
				clock);
	}

	public TokenExchangeConfiguration
	{
		externalIdentityClaimName = requireNonBlank(externalIdentityClaimName,
				"externalIdentityClaimName must not be blank");
		userResolver = Objects.requireNonNull(userResolver, "userResolver must not be null");
		localSubjectResolver = Objects.requireNonNull(localSubjectResolver, "localSubjectResolver must not be null");
		roleResolver = Objects.requireNonNull(roleResolver, "roleResolver must not be null");
		tokenVersionResolver = Objects.requireNonNull(tokenVersionResolver, "tokenVersionResolver must not be null");
		customClaimEnricher = Objects.requireNonNull(customClaimEnricher, "customClaimEnricher must not be null");
		clock = Objects.requireNonNull(clock, "clock must not be null");
	}

	private static String requireNonBlank(final String value, final String message)
	{
		return Unfolding.beckon(value)
		                .discern(StringSanitizationUtility::isNotBlank,
								() -> new IllegalArgumentException(message))
		                .summon();
	}
}