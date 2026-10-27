# PLAN: secp256k1 signature verification library for UdonSharp

## How to work through this plan

- Work through the phases in order. Tick each checkbox (`- [x]`) as soon as that step is done and verified.
- Do not start a phase while tests from an earlier phase are failing.
- The "Fixed decisions" section reflects choices already made by the project owner. Ask before changing any of them.
- If an SDK capability check in Phase 0 fails, record the result in the "Phase 0 findings" section at the bottom and adjust the affected steps instead of guessing.
- If a Unity automation skill is available in this project (editor control, compile, play mode), use it for compiling and running tests rather than asking the user to do it manually.

## Goal

An UdonSharp library that verifies that a string was signed by a known authority with ECDSA over secp256k1. It will be used by a separate world project to validate signed admin access tokens, but this library knows nothing about tokens. It is given a string and a signature and answers valid or invalid.

The library also provides a nonce generator for the consuming project.

## What is signed

The authority signs as follows:

1. `hash = SHA-256(UTF-8 bytes of data)`
2. ECDSA-sign the 32-byte `hash` on secp256k1, with no further hashing by the signing library.
3. Output the signature as 65 bytes, hex-encoded (130 characters): `r` (32 bytes) || `s` (32 bytes) || `v` (1 byte).

The library must reproduce step 1 exactly and verify step 2.

## Fixed decisions

- Scope: the library treats `data` as an opaque string. It hashes the UTF-8 bytes and verifies the signature, nothing else. It never parses `data` or any surrounding JSON, and has no knowledge of tokens, display names, nonces or expiry.
- Public surface:
  - `bool Verify(string data, string signatureHex)`: blocking, for tests, tooling and callers that can tolerate a long frame.
  - A frame-sliced request API taking the same two inputs, with a request ID, reporting valid or invalid to a caller-supplied `UdonSharpBehaviour` through a callback event.
  - `string NewNonce()`: lowercase UUID-style nonce (see Phase 10).
- Curve and scheme: ECDSA over secp256k1. Verification only. No private keys or signing code.
- Message hash: single SHA-256 of the UTF-8 bytes of `data`, used directly as `z`.
- Signature: 65-byte `r||s||v`. `v` is ignored (the public key is known, so no recovery is needed). Accept upper- and lowercase hex.
- Low-s is not enforced. Signature malleability is irrelevant because the signature only authenticates `data`.
- The authority public key is set as an inspector field on the verifier, in uncompressed form (`04 || x || y`, 130 hex chars), so no point decompression is needed at runtime. The key is validated once at startup.
- Nonce format: random, large enough to never collide, lowercase UUID-style string (8-4-4-4-12 hex). No uppercase anywhere.

## Architecture

All code under `Assets/Secp256k1Udon/` (rename if the project owner prefers), with tests in a `Tests/` subfolder that the consuming project does not need to copy.

| Component | Responsibility |
|---|---|
| `Sha256` | SHA-256 over `byte[]` |
| `Utf8` | Manual UTF-8 encoder for `string` (including surrogate pairs) |
| `Hex` | Hex string to `byte[]`, `byte[]` to lowercase hex |
| `U256` | 256-bit limb arithmetic helpers, field arithmetic mod p, scalar arithmetic mod n |
| `Secp256k1` | Jacobian point double/add, Shamir double-scalar multiplication, blocking ECDSA verify |
| `SignatureVerifier` | Holds the public key; frame-sliced verification state machine with a request queue |
| `NonceGenerator` | Lowercase UUID-style nonce |

UdonSharp constraints to design around:
- No `System.Numerics`, no `System.Security.Cryptography`. All crypto is hand-written.
- No user-defined structs, no generics, no operator overloading. Represent numbers as `uint[]` limbs and points as flat `uint[]` arrays with offsets.
- Every extern call in Udon is expensive. Minimize operation count, and preallocate scratch buffers as fields instead of allocating arrays per operation.
- Use 8 x 32-bit limbs (little-endian limb order) with `ulong` intermediates for products and carries. Cast to `ulong` before multiplying.
- Narrowing casts are checked in Udon (see Phase 0 findings): always mask before narrowing, e.g. `(uint)(x & 0xFFFFFFFFUL)`, `(byte)(x & 0xFFu)`. An unmasked cast of an out-of-range value throws and halts the behaviour.

## Phases

### Phase 0: Project setup and SDK capability checks

- [x] Confirm the installed VRChat SDK and UdonSharp versions and record them below.
- [x] Create the folder structure and an assembly layout UdonSharp accepts.
- [x] Check whether `System.Guid.NewGuid()` is exposed to Udon.
- [x] Check whether `System.Text.Encoding.UTF8` is exposed (informational only; the plan uses a manual encoder regardless).
- [x] Check whether `System.Diagnostics.Stopwatch` is exposed, for timing measurements.
- [x] Confirm `uint`/`ulong` overflow wraps in Udon the same way as in C# (unchecked), with a small play-mode test.

### Phase 1: Reference test vectors

#### ECSandbox (reference signer)

`ECSandbox.jar` is provided by the user at the project root. It uses the same signing library as the authority token generator, so its output is the ground truth. It is listed in `.git/info/exclude`: never commit it, never copy it into `Assets/`, and never make the library or the Unity tests depend on it. It is only used to generate the committed vectors file; once that file exists, the tests run without the jar. If the jar is missing, ask the user for it instead of substituting another signing library.

Commands (all values are hex; output on stdout):

| Command | Arguments | Output |
|---|---|---|
| `java -jar ECSandbox.jar secp256k1 gen` | none | 3 lines: `Private: <64 hex>`, `Public:  <130 hex, 04-prefixed>`, `CPublic: <66 hex, compressed>` (note the padding spaces after `Public:`; split on whitespace) |
| `java -jar ECSandbox.jar secp256k1 signrsv <privateKey> <hash>` | private key, 32-byte message hash | 130-hex signature `r||s||v` |
| `java -jar ECSandbox.jar secp256k1 verify <publicKey> <hash> <signature>` | uncompressed public key, 32-byte hash, signature | `OK` (exit code 0) or `Fail` (exit code 1) |

ECSandbox signs and verifies the hash exactly as given. The caller computes `SHA-256(UTF-8(data))` first and passes that hash in hex.

Known-good example (already checked independently with a textbook ECDSA verification):
- Public: `0482c0b07b91d483e3f8f3c1c5336512da70e559db264554a4f3dba8b6da2875a7351728ff3b584a105cb4d992fba5584f64919374f136c2137455655cc4095e82`
- Hash: `f0ec4ead0758e7fc50cb73cfa1eb97626637a934ec8f8c1bb7c20a2cc5ac1ddc` (SHA-256 of the 65 raw bytes of the public key above, not of its hex string)
- Signature: `17e4684dd69e178639d8fc8c7412c3e764ace8f8d407cb2572ca03caf75650f1c343df2ce4839762e0be9c9bfd1cf0b0aabebe8efaa364df305781877d83dd2601`

Observations from this example:
- `v` is `00`/`01` (recovery ID), not 27/28. The library still ignores it.
- The `s` in this signature is high (greater than n/2), so the signing library does not normalize to low-s. Accepting high-s is required, not optional.
- This example is a hash-level vector (no `data` string). Add it to the vectors with an entry point that verifies a precomputed hash, so it can test the ECDSA core independently of SHA-256 and UTF-8.

#### Steps

- [x] Confirm `ECSandbox.jar` is present at the project root and that `.git/info/exclude` lists it. Run the example above through `verify` and confirm `OK`.
- [x] Write the generator as a single-file Java program, `Tools/GenVectors.java`, run with `java Tools/GenVectors.java` (no build step). It computes SHA-256 with `MessageDigest`, encodes with `StandardCharsets.UTF_8`, calls ECSandbox through `ProcessBuilder` (checking exit codes), and writes the vectors file. Field, scalar and point vectors are computed in the same program with `BigInteger`.
- [x] Generate a throwaway test key pair with `gen`. Only the public key goes into the vectors file; the private key is not committed. Never use or commit the authority's real private key.
- [x] Have the generator cross-check every signature with ECSandbox `verify` before writing it, and use `verify` to record the expected result for each derived invalid case. If ECSandbox's verdict differs from the expected result listed below (for example on high-s or a changed `v`), stop and report it to the user.
- [x] Produce a vectors file in `Tests/` (JSON or a C# constants file) containing:
  - [x] The ECSandbox example above as a hash-level vector.
  - [x] SHA-256 vectors: empty string, `"abc"`, a 55-byte, a 56-byte, a 64-byte and a 1000-byte message, and strings with non-ASCII characters (including one outside the BMP).
  - [x] Field and scalar arithmetic vectors (mul, square, inverse) including edge values: 0, 1, p-1, n-1, values near 2^256.
  - [x] Point vectors: G, 2G, 3G, a random kG.
  - [x] At least 10 valid `(data, signatureHex)` pairs with the test public key. Include arbitrary `data` strings (empty, plain text, JSON, non-ASCII), since the library must not depend on the content.
  - [x] Invalid cases: modified `data` (one character), modified `r`, modified `s`, `r = 0`, `s = 0`, `r >= n`, `s >= n`, wrong public key, a high-s variant of a valid signature (expected: valid), `v` changed (expected: valid), malformed signature hex (wrong length, non-hex characters).
  - [x] Public key cases: valid uncompressed key, key not on the curve, wrong prefix byte, wrong length.
  - File: `Assets/Secp256k1Udon/Tests/Vectors/vectors.json` (ASCII, non-ASCII text as `\uXXXX`). Every entry with `data` also stores its expected `utf8` bytes. Beyond the list above it has field/scalar `add`, `sub` and `reduce` (for non-canonical values in [p, 2^256) and z in [n, 2^256)), unpaired-surrogate UTF-8 cases (U+FFFD), `doubleMul` vectors for u1·G + u2·Q (including the doubling and infinity cases), an n − s counterpart of every valid signature (`signatureFlips`), and uppercase-hex signatures and keys. Rerunning the generator makes a new key pair and new signatures. ECSandbox agreed with every expected result.

### Phase 2: Testing harness

- [x] Create an EditMode test path that exercises the library as plain C#, for fast correctness iteration. `Tests/VectorTests.cs` is one `UdonSharpBehaviour` holding all vector checks; the NUnit test `Tests/Editor/VectorTestsEditMode.cs` instantiates it and calls `RunAll()` as plain C#. Menu `Tools/Secp256k1Udon/Run EditMode Tests` runs it and logs `[EditModeTests] done: N passed, M failed`.
- [ ] Create a play-mode Udon test behaviour that runs the same vectors inside the Udon VM and logs PASS/FAIL per case with a summary line.
- [ ] Treat the Udon run as authoritative. EditMode passing is necessary but not sufficient.

### Phase 3: Byte utilities

- [ ] `Hex`: parse hex (either case) to `byte[]`, reject odd length and non-hex characters; encode `byte[]` to lowercase hex.
- [ ] `Utf8`: encode `string` to UTF-8 bytes, handling surrogate pairs; replace unpaired surrogates with U+FFFD bytes.
- [ ] Conversions between 32-byte big-endian `byte[]` and 8-limb `uint[]`.
- [ ] Tests pass in EditMode and in Udon.

### Phase 4: SHA-256

- [ ] Implement SHA-256 over `byte[]` with preallocated message schedule buffers.
- [ ] All SHA-256 vectors pass in EditMode and in Udon.

### Phase 5: Field arithmetic mod p

p = 2^256 - 2^32 - 977.

- [ ] Add, subtract, compare, conditional subtract.
- [ ] Multiply and square: 8x8 schoolbook product into 16 limbs, then reduce using 2^256 ≡ 0x1000003D1 (mod p): fold the high half twice, then a final conditional subtract.
- [ ] Inverse is not needed for verification (see Phase 8). Implement it only if a test or debug path needs affine coordinates.
- [ ] All operations work in place on preallocated buffers; no per-call allocations.
- [ ] Tests pass in EditMode and in Udon.

### Phase 6: Scalar arithmetic mod n

n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141.

- [ ] Reduce a 256-bit value mod n (the hash `z` can exceed n).
- [ ] Multiply mod n (Barrett, Montgomery, or simple shift-and-subtract; this runs only a few times per verification, so prefer the simplest correct option).
- [ ] Inverse mod n (Fermat exponentiation with n-2, or binary extended Euclid).
- [ ] Tests pass in EditMode and in Udon.

### Phase 7: Curve operations

- [ ] Jacobian point doubling for a = 0.
- [ ] Jacobian point addition (Jacobian + Jacobian, or mixed with affine where cheaper), with correct handling of: either input at infinity, P == Q (fall back to doubling), P == -Q (result at infinity).
- [ ] Shamir double-scalar multiplication `u1·G + u2·Q`: precompute `G + Q`, then one shared double-and-add loop over 256 bits.
- [ ] Public key validation: prefix `04`, correct length, coordinates below p, point on the curve (`y² = x³ + 7 mod p`). Run once when the key is loaded; an invalid key makes every verification fail and logs an error.
- [ ] Tests (2G, 3G, kG, u1·G + u2·Q, public key cases) pass in EditMode and in Udon.

### Phase 8: ECDSA verify (blocking)

Inputs are `data` (opaque string) and `signatureHex`. The library does not inspect the content of `data`.

- [ ] Parse signature: exactly 130 hex chars, split into `r`, `s`, ignore `v`.
- [ ] Reject unless `1 <= r <= n-1` and `1 <= s <= n-1`.
- [ ] `z = SHA-256(UTF-8(data)) mod n`.
- [ ] Split the core into a hash-level method (`VerifyHash(byte[] hash32, string signatureHex)`) that `Verify` calls after hashing, so hash-level vectors such as the ECSandbox example can be tested directly.
- [ ] `w = s⁻¹ mod n`, `u1 = z·w mod n`, `u2 = r·w mod n`.
- [ ] `R = u1·G + u2·Q`; reject if `R` is at infinity.
- [ ] Without inverting: accept if `r·Z² ≡ X (mod p)`; otherwise, if `r + n < p`, accept if `(r + n)·Z² ≡ X (mod p)`; otherwise reject.
- [ ] Any malformed input returns `false` without throwing (Udon has no try/catch, so an exception would halt the behaviour).
- [ ] All valid and invalid vectors give the expected result in EditMode and in Udon.

### Phase 9: Frame-sliced verifier

- [ ] Convert Phase 8 into a state machine: parse/hash, scalar setup, N loop iterations per frame, final comparison.
- [ ] Drive it with `SendCustomEventDelayedFrames` (or `Update` while busy). Use one shared verifier with a queue, so multiple requests are processed one at a time.
- [ ] Request API: caller passes `data`, `signatureHex`, a caller `UdonSharpBehaviour`, a callback event name, and a request ID. On completion the verifier sets the result (request ID, valid/invalid) in fields the caller can read, then calls the event on the caller. Document the exact field names.
- [ ] Define queue behaviour when full (fixed capacity, reject new requests and report invalid, or grow) and document it.
- [ ] Measure total verification time and per-frame cost in Udon. Pick N so the per-frame cost stays below about 2 ms on a typical desktop client, and expose N as an inspector field. Record the measurements below.
- [ ] Valid and invalid vectors still pass through the sliced path, including several queued requests at once.

### Phase 10: Nonce generator

- [ ] If `System.Guid.NewGuid()` is exposed, use `NewGuid().ToString()` (lowercase "D" format) and verify it is lowercase.
- [ ] Otherwise: SHA-256 over a byte buffer combining several entropy sources (several `UnityEngine.Random` values, `DateTime.UtcNow.Ticks`, `Time.realtimeSinceStartup`, network server time, local player ID and display name). Take the first 16 bytes, set the UUID version-4 and variant bits, format as lowercase 8-4-4-4-12.
- [ ] Test: generate 10,000 nonces, confirm format (regex `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`) and no duplicates.

### Phase 11: Packaging and documentation

- [ ] Add a `README.md` in the library folder covering: what the library does and does not do, the signing procedure the authority must follow, how to set the public key, the blocking and sliced APIs with a minimal UdonSharp usage example for each, `NewNonce()`, the measured performance, and which folders to copy into another project (library only, not tests or tools).
- [ ] Confirm the library compiles in a clean project with only the VRChat Worlds SDK and UdonSharp installed (no dependency on test code or `Tools/`).
- [ ] Final full test run, EditMode and Udon, all passing.

## Phase 0 findings

- VRChat SDK version: Worlds SDK 3.10.5 (`com.vrchat.base` and `com.vrchat.worlds` 3.10.5, VPM resolver 0.1.29), Unity 2022.3.22f1.
- UdonSharp version: bundled with `com.vrchat.worlds` 3.10.5 (`Integrations/UdonSharp`), not installed as a separate package.
- `System.Guid.NewGuid()`: exposed. `NewGuid().ToString()` gives the lowercase "D" format in Udon, e.g. `bccee525-df6d-4611-9c88-7b56e31bf88c` (`GuidProbe`).
- `Encoding.UTF8`: exposed. `GetBytes` on a 2-byte, 3-byte and 4-byte (surrogate pair) character gives the expected 10 bytes (`Utf8Probe`). The plan still uses the manual encoder.
- `Stopwatch`: exposed (`StartNew`, `Stop`, `Elapsed`, `ElapsedTicks`, `Frequency`, 10 MHz). For a rough sense of Udon speed: a 10,000-iteration `sum += i` loop took 2.47 ms in the editor, about 0.25 µs per iteration (`StopwatchProbe`).
- Integer overflow behaviour: arithmetic wraps like unchecked C#. `uint`, `ulong` and `int` add, subtract, multiply and shift all wrap, and the `(ulong)a * b` full product is correct (`Phase0Probe`, 15/15 pass). **Narrowing casts do not wrap.** Udon compiles them to checked `System.Convert` calls (`SystemConvert.__ToUInt32__SystemUInt64__SystemUInt32`), so `(uint)someUlong` with a value above `uint.MaxValue` throws "Value was either too large or too small for a UInt32" and halts the behaviour. Masking first works: `(uint)(x & 0xFFFFFFFFUL)`, `(byte)(x & 0xFFu)`. Expect the same for any other narrowing or sign-changing cast, e.g. `(uint)` of a negative `int`.

## Measurements

- Full verification time in Udon (blocking):
- Iterations per frame chosen:
- Per-frame cost at that setting:
- Frames per verification:
