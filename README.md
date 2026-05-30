# SAMLn (Security Assertion Markup Language - Next)

SAMLn is a high-performance, non-XML identity assertion engine designed for decentralized, zero-trust mesh architectures. It delivers 1:1 functional declaration mapping with the **SAML 2.0 Core Specification** (including Subjects, Conditions, Audience Restrictions, and Attribute Statements) while replacing the heavy, legacy W3C XMLDSIG/C14N processing layer with standard, linear JSON Web Signatures (JWS).

By utilizing a human-readable, declarative grammar adapted from the GML syntax, SAMLn eliminates entire classes of enterprise security risks (such as XML External Entity injection, XML Entity Expansion, and SAML Signature Wrapping) while maintaining complete cryptographic enforcement via hardware-backed primitives.

---

## Architecture Overview

Traditional SAML implementations are prone to implementation bugs due to the complexity of XML Canonicalization (C14N), where structural changes to whitespace or attribute order alter cryptographic hashes. SAMLn bypasses this entirely:

1. **Compilation Phase:** The engine parses a declarative SAMLn script into an Abstract Syntax Tree (AST).
2. **Claim Synthesis:** Validated AST nodes map point-for-point to standard SAML core statement matrices.
3. **Envelope Generation:** Compiled claim maps are serialized into a linear JSON dictionary and sealed atomically into a standard `RS256` JSON Web Token (JWT).
4. **Hardware Enforcement:** Verification pipelines intercept inbound tokens, extract the declared subject, pull the authoritative machine public key bytes from the `ultimate_db` OCC cache or persistent table tier, and validate the physical TPM/DBSC signature signatures natively via `service_keys`.

---

## Core Language Specification

Instead of verbose XML boilerplate, SAMLn policies are written using clean, declarative block matrices:

```text
assertion#saml-claim-vector-9901 :issueInstant."2026-05-29T21:13:04Z" (
    issuer("[https://idp.gddisney.io](https://idp.gddisney.io)"),
    subject(
        nameid:format."urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"("gregory.disney@servicekeys.io"),
        subjectconfirmation:method."urn:oasis:names:tc:SAML:2.0:cm:bearer"(
            subjectconfirmationdata:notonorafter."15m":recipient."[https://sp.servicekeys.cloud/saml/consume](https://sp.servicekeys.cloud/saml/consume)"()
        )
    ),
    conditions:notbefore."0m":notonorafter."1h" (
        audiencerestriction(
            audience("[https://sp.servicekeys.cloud/saml/metadata](https://sp.servicekeys.cloud/saml/metadata)")
        )
    ),
    hardwaresignature:keytype."TPM_RSA":proof."BASE64_TPM_REPLAY_PROOF_STRING" (
        tpmpubkey("ignored-metadata-layer")
    ),
    devicebinding:sessionref."session_jti_001":challenge."nonce_99182" (
        dbscpubkey("MOCK_DBSC_JWK_METADATA_STR")
    ),
    attribute:name."memberOf" (
        attributevalue("security_engineers"),
        attributevalue("administrators")
    )
)

```

### 1:1 Mapping Matrix

| SAMLn Declarative Node | SAML 2.0 Core Element Equivalent | Target JWS JWT Target Location |
| --- | --- | --- |
| `assertion#ID` | `<saml:Assertion ID="...">` | `claims["jti"]` |
| `issuer("...")` | `<saml:Issuer>` | `claims["iss"]` |
| `nameid:format."..."("...")` | `<saml:NameID Format="...">` | `claims["sub"]` / `claims["saml:NameIDFormat"]` |
| `subjectconfirmation:method` | `<saml:SubjectConfirmation>` | `claims["saml:SubjectConfirmation"]["Method"]` |
| `conditions:notonorafter` | `<saml:Conditions NotOnOrAfter="...">` | `claims["exp"]` (Absolute Unix Timestamp) |
| `audiencerestriction(...)` | `<saml:AudienceRestriction>` | `claims["aud"]` (Array of audience strings) |
| `hardwaresignature(...)` | *Extension Primitive* | `claims["saml:HardwareSignature"]` (TPM Proof Matrix) |
| `devicebinding(...)` | *Extension Primitive* | `claims["saml:DeviceBinding"]` (DBSC Nonce Matrix) |
| `attribute:name."..."` | `<saml:Attribute Name="...">` | `claims["saml:AttributeStatement"][Name]` |

---

## API Reference

### Initializing the Engine

Initialize the SAMLn engine by passing your underlying database instance, your issuer identity string, your private RSA signing key, and the specific database `PageID` layout where authoritative user identity profiles reside:

```go
import (
    "crypto/rsa"
    "[github.com/gddisney/samln](https://github.com/gddisney/samln)"
    "[github.com/gddisney/ultimate_db/v2](https://github.com/gddisney/ultimate_db/v2)"
)

// Initialize the core assertion module
engine, err := samln.New(db, "[https://idp.servicekeys.io](https://idp.servicekeys.io)", privateKey, ultimate_db.PageID(1))

```

### Compiling an Assertion

Compile a human-readable SAMLn schema string into a signed cryptographic token envelope container:

```go
variables := map[string]interface{}{
    "custom_context_variable": "runtime_value",
}

tokenString, err := engine.CompileSAMLnString(samlScript, variables)

```

### Validating a Hardware Assertion

Intercept an inbound token string and validate it against the authoritative hardware registry. The verification pipeline bypasses any user metadata embedded inside the token string and evaluates signatures against the real public key bytes extracted directly from the lock-free database cache storage layer:

```go
isValid, err := engine.ValidateHardwareAssertion(tokenString, "expected_nonce_challenge")
if err != nil {
    // Handle validation or cryptographic verification failures explicitly
}

```

---

## Operational Validation Matrix

To verify compilation stability and assert that hardware cryptographic bounds execute flawlessly against your `ultimate_db` layers, run the full test package suite:

```bash
go test -v ./...

```

```

```
