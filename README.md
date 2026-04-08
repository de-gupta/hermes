# hermes

Hermes is the issuer and exchange authority for internal tokens.

Its job is to accept a raw upstream token, verify that token through Themis, resolve the trusted upstream identity to a
local user, enrich local claims such as roles and token version, and mint a new internal token that downstream services
can trust.

Hermes is intentionally not:

- a full authentication framework
- a user-management library
- an authorization engine
- a currentness or revocation checker

## Philosophy

Hermes exists to keep token issuance and token exchange separate from the other security concerns in the ecosystem.

- `themis` trusts tokens cryptographically
- `hermes` mints and exchanges tokens
- `augustus` checks whether trusted tokens are still current in system state
- `argus` orchestrates the whole pipeline

That separation matters.

- Trusting a token is not the same as issuing a token.
- Issuing a token is not the same as deciding whether it is still current.
- Currentness is not the same as authorization.
- Authentication should not collapse crypto, DB state, issuance, and framework glue into one unstable abstraction.

Hermes therefore focuses on one narrow responsibility:

- take a trusted upstream identity
- translate it into a local/internal identity
- enrich the claims that belong in the internal token
- issue the internal token

## What Consumers Provide

Hermes is framework-agnostic and deliberately does not know your user model, database schema, or IdP-specific domain
model.

Consumers provide:

- an upstream-token verification strategy, either as a Themis verifier or as verification settings for the built-in
  HMAC, RSA, or EC paths
- a way to resolve an upstream identity to a local user
- a way to derive the local/internal subject from that user
- a way to fetch the roles for that user
- a way to fetch the token version for that user
- optional custom claim enrichment
- the signing key material for the internal token that Hermes should mint

Conceptually, that looks like:

```java
interface UserResolver<ExternalIdentity, User>
{
    Optional<User> resolveUser(ExternalIdentity externalIdentity);
}

interface LocalSubjectResolver<User>
{
    String resolveSubject(User user);
}

interface RoleResolver<User>
{
    Set<String> fetchRoles(User user);
}

interface TokenVersionResolver<User>
{
    long resolveVersion(User user);
}

interface CustomClaimEnricher<User>
{
    Map<String, ?> enrich(User user, NormalizedToken upstreamToken);
}
```

## What Consumers Get

Consumers get:

- a small exchange API that accepts a raw upstream token
- internal upstream-token verification through Themis
- configurable extraction of the upstream identity claim, defaulting to `sub`
- explicit success and failure result types instead of exception-driven control flow for normal invalid cases
- a newly minted internal JWT with local subject, version, roles, issuer, timing claims, and optional custom claims
- support for HMAC, RSA, and EC signing of the internal token

The current exchange result model distinguishes:

- successful exchange with an issued token
- upstream verification failure
- missing external identity
- unresolved local user
- missing local subject
- internal issuance failure

## Public API

The public API is intentionally small.

Main entrypoint:

- `TokenExchangeServiceFactory`

Main service:

- `TokenExchangeService`

Main configuration/value types:

- `TokenExchangeConfiguration`
- `TokenIssuancePolicy`
- `ExchangeResult`
- `ExchangeSuccess`
- `ExchangeFailure`
- `ExchangeFailureReason`
- `IssuedToken`

Consumer extension seams:

- `UserResolver`
- `LocalSubjectResolver`
- `RoleResolver`
- `TokenVersionResolver`
- `CustomClaimEnricher`

## Usage

The example below is intentionally shown without exact package imports so the README stays stable if package names move.
The flow itself is complete.

```java
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

record LocalUser(String id, String externalId, String tenantId)
{
}

final class Example
{
  ExchangeResult exchange(final String upstreamToken)
  {
    TokenIssuancePolicy issuancePolicy = TokenIssuancePolicy.of(
            "https://auth.internal.example",
            Set.of("inventory-api"),
            Duration.ofMinutes(30));

    TokenExchangeConfiguration<LocalUser> configuration = TokenExchangeConfiguration.of(
            "sub",
            this::findLocalUser,
            LocalUser::id,
            user -> fetchRoleNames(user.id()),
            user -> fetchTokenVersion(user.id()),
            (user, trustedUpstreamToken) -> Map.of("tenant", user.tenantId()),
            Clock.systemUTC());

    TokenExchangeService exchangeService = TokenExchangeServiceFactory.rsa(
            TokenVerificationPolicy.of(Duration.ofSeconds(30), true),
            upstreamIssuerPublicKey(),
            issuancePolicy,
            internalIssuerPrivateKey(),
            configuration);

    return exchangeService.exchange(upstreamToken);
  }

  private Optional<LocalUser> findLocalUser(final String externalId)
  {
    return Optional.of(new LocalUser("local-42", externalId, "acme"));
  }

  private Set<String> fetchRoleNames(final String localUserId)
  {
    return Set.of("ROLE_ADMIN", "ROLE_REPORTING");
  }

  private long fetchTokenVersion(final String localUserId)
  {
    return 7L;
  }

  private RSAPublicKey upstreamIssuerPublicKey()
  {
    throw new UnsupportedOperationException("provide your upstream RSA public key");
  }

  private RSAPrivateKey internalIssuerPrivateKey()
  {
    throw new UnsupportedOperationException("provide your internal RSA private key");
  }
}
```

Typical handling looks like:

```java
ExchangeResult result = exchangeService.exchange(upstreamToken);

if (result instanceof ExchangeSuccess success)
{
    String internalToken = success.token().token();
String localSubject = success.token().subject();
}
else if (result instanceof ExchangeFailure failure)
{
        switch(failure.

reason())
        {
        case UPSTREAM_VERIFICATION_FAILED ->{
        // reject the request
        }
        case MISSING_EXTERNAL_IDENTITY,USER_NOT_FOUND,MISSING_LOCAL_SUBJECT ->{
        // reject the request
        }
        case ISSUANCE_FAILED ->{
        // treat as server-side fault
        }
    }
}
```

The issued internal token currently contains:

- local subject
- internal issuer
- configured audience, if any
- issue and expiry timestamps
- roles
- token version
- optional token id
- optional upstream issuer claim
- custom claims from the consumer-provided enricher

Hermes intentionally writes the canonical issuance claims itself even if custom enrichment returns the same keys.