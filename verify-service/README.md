# Inji Verify Backend Service

`verify-service` is the standalone Spring Boot app: controllers, exception-to-HTTP-response
mapping, and app bootstrapping. The framework-agnostic domain logic (DTOs, validation, DCQL/VP
business logic, persistence) lives in [`verify-core`](../verify-core/README.md), which
`verify-service` depends on and which can also be embedded directly by another Spring app — see
that module's README if you want to consume Inji Verify as a library rather than run it as a
service.

### Contents
* Features
* Standards
* Setup Guide
* API docs


#### Features
* ###### VC Verification
  It offers an API for verifying VCs on the server side. The API takes a VC as input and carries out validation and proof verification using the [vc-verifier](https://github.com/mosip/vc-verifier/tree/master/vc-verifier/kotlin) module.

* ###### OpenID4VP Sharing
  It is designed to support OpenID4VP specification. The current supported draft is [draft 21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html).

#### Standards
  For OpenID4VP Sharing below are the supported features.
- Cross Device Flow
- Same Device Flow
- `response_type` as `vp_token`
- `response_mode` as `direct_post`
- Verifiable Presentation proofs supported are `ED25519Signature2018`, `ED25519Signature2020` and `RSASignature2018`

Out of scope items are
- `response_type` with `vp_token id_token`
- `response mode` with `direct_post.jwt
##### Setup Guide

<<<<<<< HEAD
The link to set up guide can be found [here](../Readme.md).

##### API docs

The API docs are published in Stoplight, which can be found [here](https://mosip.stoplight.io/docs/inji-verify/branches/main).

#### Using verify-service as a Library Dependency

`verify-service` publishes a plain JAR (without bundled dependencies) that can be consumed by other Maven projects.

Add the following to your `pom.xml`:

**Dependency:**
```xml
<dependency>
    <groupId>io.inji.verify</groupId>
    <artifactId>verify-service</artifactId>
    <version>${verify-service.version}</version>
</dependency>
```

**Repositories:**

Some transitive dependencies are not available on Maven Central. Ensure the following repositories are configured in your `pom.xml` or `settings.xml`:

- **Sonatype (INJI snapshots)** — for `io.inji` artifacts (`vcverifier-jar`, `pixelpass-jar`)
- **Danubetech** — for `ld-signatures-java` and `jsonld-common-java`
- **Google Maven** — for `com.android.identity:identity-credential`

Maven will automatically resolve all transitive dependencies from the published POM.
=======
> **Never build `verify-service` standalone** (i.e. don't `cd verify-service` and run `mvn ...`
> directly). It depends on the sibling `verify-core` module; building it alone resolves
> `verify-core` from your `~/.m2` cache instead of from current source, which will silently use a
> **stale** `verify-core` jar if it's changed since your last install — leading to confusing
> `NoClassDefFoundError`s at runtime that don't reproduce with `mvn test`/`spring-boot:run`. Always
> build from the **repo root**.

```shell
cd inji-verify                        # repo root, not verify-service
mvn clean install -Dgpg.skip          # builds + installs verify-core and verify-service together
```

Run/test individual pieces from the repo root once that's built:

```shell
mvn -pl verify-service -am spring-boot:run                                # HSQLDB in-memory (default, no DB setup needed)
mvn -pl verify-service -am spring-boot:run -Dspring.profiles.active=local  # same, explicitly
mvn -pl verify-service test -Dtest=VPRequestControllerTest                # run a single test class
```

For PostgreSQL (production), apply the scripts in `db_scripts/` manually. `spring.jpa.hibernate.ddl-auto` is set to `none` for production profiles.

##### Docker

```shell
cd inji-verify                    # repo root
mvn clean install -Dgpg.skip
cd verify-service
docker build -t <dockerImageName>:<tag> .
docker run -it -d -p 3000:8000 --env-file ./.env --name inji-verify-service-dev <dockerImageName>:<tag>
```

To build with the local HSQLDB profile:

```shell
docker build --build-arg active_profile=local -t <dockerImageName>:<tag> .
```

Stop and delete containers:

```shell
docker stop inji-verify-service-dev
docker rm inji-verify-service-dev
```

##### API docs

The API docs are published on Stoplight: [Inji Verify API documentation](https://mosip.stoplight.io/docs/inji-verify/branches/main).
>>>>>>> 73095bd4 (#2148 split into two components verify-core and verify-service (#2231))
