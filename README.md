# hermes

Hermes is the token issuer and token exchange authority of the ecosystem.

Its job is to accept an upstream identity proof that has been verified cryptographically, resolve that identity to a local user, enrich local claims such as roles and token version, and mint a new internal token that downstream services can trust and use.

In the intended stack:

- `themis` verifies tokens cryptographically and normalizes trusted claims.
- `hermes` exchanges trusted upstream identity into an internal token.
- `augustus` checks whether a trusted token is still current in system state.
- `argus` orchestrates the full authentication pipeline.

Hermes is not a full authentication framework, authorization engine, or user-management library.

## Current scope

The current initial implementation supports:

- raw upstream JWT input
- internal verification of that upstream token via `themis`
- configurable external identity claim extraction, defaulting to `sub`
- local user resolution through a consumer-provided interface
- local role resolution through a consumer-provided interface
- token version resolution through a consumer-provided interface
- custom claim enrichment through a consumer-provided interface
- HMAC signing for the issued internal token
- explicit success and failure result types for exchange

The current implementation does not yet include:

- RSA or EC signing for issued internal tokens
- a separate direct `TokenIssuer` API for already-trusted local identities
- Spring Boot starter or auto-configuration
- built-in persistence adapters
- refresh-token, login, registration, or MFA flows
- currentness validation after issuance

## Public API

The intended public entrypoint is:

- `de.gupta.hermes.api.TokenExchangeServiceFactory`

The main public configuration/value types are:

- `de.gupta.hermes.api.TokenExchangeConfiguration`
- `de.gupta.hermes.api.TokenIssuancePolicy`
- `de.gupta.hermes.domain.model.ExchangeResult`
- `de.gupta.hermes.domain.model.ExchangeSuccess`
- `de.gupta.hermes.domain.model.ExchangeFailure`
- `de.gupta.hermes.domain.model.IssuedToken`

The main extension seams that consumers implement are:

- `UserResolver<ExternalIdentity, User>`
- `LocalSubjectResolver<User>`
- `RoleResolver<User>`
- `TokenVersionResolver<User>`
- `CustomClaimEnricher<User>`

## Exchange flow

The exchange flow is:

1. an upstream IdP token arrives
2. Hermes calls a Themis verifier internally
3. Hermes extracts the configured upstream identity claim
4. Hermes resolves the local user
5. Hermes resolves local roles
6. Hermes resolves the token version
7. Hermes enriches any custom claims
8. Hermes issues a new signed internal token

After that, downstream services should use the Hermes-issued internal token only.

## What consumers need to provide

Hermes is framework-agnostic and intentionally does not know your user model or database schema.

Consumers must provide:

- a way to verify the upstream token
- a way to resolve an upstream identity to a local user
- a way to derive the internal/local subject from that local user
- a way to fetch roles for that local user
- a way to fetch the current token version for that local user
- optional custom claim enrichment
- the secret used to sign internal HMAC tokens

Conceptually, those look like this:

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

## Basic usage

### 1. Define the issuance policy

```java
TokenIssuancePolicy issuancePolicy = TokenIssuancePolicy.of(
        "https://auth.my-company.internal",
        Set.of("my-service"),
        Duration.ofMinutes(30));
```

By default this uses:

- role claim name: `roles`
- version claim name: `ver`
- upstream issuer claim name: `upstream_iss`
- token id generation: enabled

### 2. Define the exchange configuration

```java
TokenExchangeConfiguration<LocalUser> configuration = TokenExchangeConfiguration.of(
        "sub",
        externalId -> userRepository.findByExternalId(externalId),
        LocalUser::id,
        user -> roleRepository.findRoleNamesByUserId(user.id()),
        user -> tokenVersionRepository.findVersionByUserId(user.id()),
        (user, upstreamToken) -> Map.of("tenant", user.tenantId()),
        Clock.systemUTC());
```

If you omit the claim name, Hermes uses `sub` by default.

### 3. Create the exchange service

If Hermes should verify the upstream token internally with Themis using HMAC:

```java
TokenExchangeService exchangeService = TokenExchangeServiceFactory.hmac(
        TokenVerificationPolicy.of(Duration.ofSeconds(30), true),
        upstreamIssuerSecret,
        issuancePolicy,
        internalIssuerSecret,
        configuration);
```

If you already have a Themis verifier:

```java
TokenVerifier upstreamVerifier = TokenVerifierFactory.hmac(
        TokenVerificationPolicy.of(Duration.ofSeconds(30), true),
        upstreamIssuerSecret);

TokenExchangeService exchangeService = TokenExchangeServiceFactory.hmac(
        upstreamVerifier,
        issuancePolicy,
        internalIssuerSecret,
        configuration);
```

### 4. Exchange the token

```java
ExchangeResult result = exchangeService.exchange(externalToken);

if (result instanceof ExchangeSuccess success)
{
    String internalToken = success.token().token();
}
else if (result instanceof ExchangeFailure failure)
{
    ExchangeFailureReason reason = failure.reason();
}
```

## Claim contract of the issued internal token

The current implementation emits these claims:

- `sub`: local/internal user id
- `iss`: internal issuer
- `aud`: configured audiences, if any
- `iat`: issue timestamp
- `exp`: expiry timestamp
- `jti`: optional token id when enabled
- `roles`: local roles by default, configurable claim name
- `ver`: local token version by default, configurable claim name
- `upstream_iss`: copied upstream issuer when present and enabled
- any custom claims from `CustomClaimEnricher`

Hermes intentionally overwrites reserved issuance claims like roles, version, and upstream issuer from its own authoritative data even if custom enrichment returns the same keys.

## Failure model

Hermes uses explicit result models instead of using exceptions for normal invalid cases.

Current failure reasons are:

- `UPSTREAM_VERIFICATION_FAILED`
- `MISSING_EXTERNAL_IDENTITY`
- `USER_NOT_FOUND`
- `MISSING_LOCAL_SUBJECT`
- `ISSUANCE_FAILED`

Typical handling is:

- map upstream verification failure to `401 Unauthorized`
- map missing or unresolved user to `403 Forbidden` or `401 Unauthorized`, depending on your boundary
- log unexpected issuance failures as server-side faults

## Spring Boot integration example

Hermes is framework-agnostic, but it fits naturally into Spring Boot as a set of beans that your controller or filter uses.

### Example configuration

```java
@Configuration
class HermesConfiguration
{
    @Bean
    TokenExchangeService tokenExchangeService(UserRepository userRepository,
                                              RoleRepository roleRepository,
                                              TokenVersionRepository tokenVersionRepository,
                                              HermesProperties properties)
    {
        TokenIssuancePolicy issuancePolicy = TokenIssuancePolicy.of(
                properties.internalIssuer(),
                Set.of(properties.internalAudience()),
                Duration.ofMinutes(properties.internalTokenTtlMinutes()));

        TokenExchangeConfiguration<LocalUser> configuration = TokenExchangeConfiguration.of(
                properties.externalIdentityClaim(),
                externalId -> userRepository.findByExternalId(externalId),
                LocalUser::id,
                user -> roleRepository.findRoleNamesByUserId(user.id()),
                user -> tokenVersionRepository.findVersionByUserId(user.id()),
                (user, upstreamToken) -> Map.of("tenant", user.tenantId()),
                Clock.systemUTC());

        return TokenExchangeServiceFactory.hmac(
                TokenVerificationPolicy.of(Duration.ofSeconds(30), true),
                properties.upstreamIssuerSecret(),
                issuancePolicy,
                properties.internalIssuerSecret(),
                configuration);
    }
}
```

### Example controller

```java
@RestController
@RequestMapping("/auth")
class AuthController
{
    private final TokenExchangeService tokenExchangeService;

    AuthController(TokenExchangeService tokenExchangeService)
    {
        this.tokenExchangeService = tokenExchangeService;
    }

    @PostMapping("/exchange")
    ResponseEntity<?> exchange(@RequestBody ExchangeTokenRequest request)
    {
        ExchangeResult result = tokenExchangeService.exchange(request.token());

        if (result instanceof ExchangeSuccess success)
        {
            return ResponseEntity.ok(Map.of(
                    "token", success.token().token(),
                    "subject", success.token().subject(),
                    "expiresAt", success.token().expiresAt()));
        }

        ExchangeFailure failure = (ExchangeFailure) result;
        return switch (failure.reason())
        {
            case UPSTREAM_VERIFICATION_FAILED, MISSING_EXTERNAL_IDENTITY, USER_NOT_FOUND, MISSING_LOCAL_SUBJECT ->
                    ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("reason", failure.reason().name()));
            case ISSUANCE_FAILED ->
                    ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("reason", failure.reason().name()));
        };
    }
}
```

### Recommended Spring Boot responsibility split

In a Spring Boot app, a clean split is:

- controller or filter: accepts the upstream token and calls Hermes
- repository beans: resolve local user, roles, and token version
- Hermes: verifies upstream token and issues internal token
- Themis in downstream services: verifies Hermes-issued internal token
- Augustus later: checks token currentness against state

Try to avoid putting database access or authorization rules directly into web filters. Let the Hermes configuration wire in those concerns via the resolver interfaces instead.

## Testing

The current test suite covers:

- successful exchange from upstream token to internal token
- configurable identity claim extraction
- user-not-found failures
- upstream verification failures
- missing external identity failures
- missing local subject failures
- defaults and validation of public configuration types
- defensive-copy behavior of public value types

Run tests with:

```bash
mvn test
```

## Is this initial version feature complete?

It is a reasonable first vertical slice, but not a complete `1.0` of Hermes yet.

What is strong already:

- the core exchange story exists end to end
- the library boundaries are clean and aligned with Themis
- the public API surface is still small
- the extension seams are explicit and consumer-owned
- the failure model is predictable and test-backed

What still feels missing before calling it broadly feature complete:

- asymmetric signing support for internal tokens
- a direct issue API separate from exchange
- more explicit token contract documentation around reserved custom-claim names
- more negative tests around issuer/audience policy combinations and custom claim collisions
- examples for common providers such as Supabase
- eventual Spring Boot adapter or starter if ease-of-use becomes a goal

So my view is: this is a good initial version and a good foundation, but not the full feature-complete Hermes vision yet.
