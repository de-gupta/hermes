package de.gupta.hermes.api;

import java.time.Clock;
import java.util.Objects;

// TODO: convert to final class witih private constructor and static factory method - validation should happen in static factory
public record TokenExchangeConfiguration<User>(String externalIdentityClaimName,
                                               UserResolver<String, User> userResolver,
                                               LocalSubjectResolver<User> localSubjectResolver,
                                               RoleResolver<User> roleResolver,
                                               TokenVersionResolver<User> tokenVersionResolver,
                                               CustomClaimEnricher<User> customClaimEnricher,
                                               Clock clock)
{
	public TokenExchangeConfiguration
	{
		Objects.requireNonNull(externalIdentityClaimName, "externalIdentityClaimName must not be null");
		Objects.requireNonNull(userResolver, "userResolver must not be null");
		Objects.requireNonNull(localSubjectResolver, "localSubjectResolver must not be null");
		Objects.requireNonNull(roleResolver, "roleResolver must not be null");
		Objects.requireNonNull(tokenVersionResolver, "tokenVersionResolver must not be null");
		customClaimEnricher = customClaimEnricher == null ? CustomClaimEnricher.none() : customClaimEnricher;
		clock = clock == null ? Clock.systemUTC() : clock;
	}

	public static <User> TokenExchangeConfiguration<User> of(final UserResolver<String, User> userResolver,
	                                                         final LocalSubjectResolver<User> localSubjectResolver,
	                                                         final RoleResolver<User> roleResolver,
	                                                         final TokenVersionResolver<User> tokenVersionResolver)
	{
		return new TokenExchangeConfiguration<>("sub",
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
		return new TokenExchangeConfiguration<>("sub",
				userResolver,
				localSubjectResolver,
				roleResolver,
				tokenVersionResolver,
				customClaimEnricher,
				clock);
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
}