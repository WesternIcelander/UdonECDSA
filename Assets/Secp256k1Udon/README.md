# Secp256k1Udon

An UdonSharp library for VRChat worlds that checks whether a string was signed by a known authority, using ECDSA over secp256k1. You give it a string and a signature and it answers valid or invalid. It also makes random nonces.

## What it does and does not do

It does:

- Hash the UTF-8 bytes of a string with SHA-256 and verify an ECDSA secp256k1 signature of that hash against one public key, set in the inspector.
- Verify either in one blocking call (about 0.3 s in the editor, 0.5 s in the client, in a single frame) or spread over a few hundred frames (about 1 ms of work per frame), with a request queue and a callback.
- Make lowercase UUID-style nonces (`NonceGenerator.NewNonce()`).

It does not:

- Look at the content of the string. It never parses JSON, tokens, names, nonces or expiry dates. That is up to your code, after the signature has been checked.
- Sign anything or hold private keys. It only verifies.
- Recover public keys. The `v` byte of the signature is ignored.
- Accept compressed public keys. The key must be uncompressed (`04 || x || y`).
- Reject high-s signatures. Both `s` and `n - s` are accepted, because the signature only authenticates the data.

All of it is written by hand in UdonSharp (no `System.Numerics` or `System.Security.Cryptography`, which Udon doesn't have).

## How the authority signs

The authority (whatever makes the signed strings, outside VRChat) must do exactly this:

1. `hash = SHA-256(UTF-8 bytes of data)`.
2. ECDSA-sign the 32-byte `hash` on secp256k1, with no further hashing by the signing library (sign the digest itself, not a message that the library hashes again).
3. Output the signature as 65 bytes, hex-encoded (130 characters): `r` (32 bytes, big-endian) || `s` (32 bytes, big-endian) || `v` (1 byte, any value).

Upper- and lowercase hex are both accepted. Any other length, or a character that isn't hex (in `v` too), makes the signature invalid. So do `r` or `s` equal to 0 or not below the curve order `n`.

The string you pass to the verifier must be exactly the string that was signed, character for character. Unpaired UTF-16 surrogates are encoded as U+FFFD, like most UTF-8 encoders do.

## Setting the public key

1. Add an empty GameObject to your scene and add the `SignatureVerifier` UdonSharp behaviour to it.
2. Paste the authority's public key into **Public Key Hex**: the uncompressed form, `04` followed by the 32-byte `x` and `y` coordinates, 130 hex characters in all.

The key is checked once, at `Start` or on the first call, whichever comes first: prefix `04`, 130 hex characters, both coordinates below `p`, and the point on the curve. An invalid key logs an error (`[SignatureVerifier] invalid public key on <object>`) and every verification returns invalid. `IsKeyValid()` tells you whether the key was accepted.

The other inspector fields:

| Field | Default | Meaning |
|---|---|---|
| `iterationsPerFrame` | 1 | Work per frame for `RequestVerify`. 1 is about 1 ms per frame in the editor and 1.5 ms in the client, for about 305 frames per verification. Higher values finish sooner but cost more per frame (2 is about 2 ms). |
| `queueCapacity` | 16 | Most `RequestVerify` requests waiting at once, besides the one running. |

Keep the verifier's GameObject active while requests are pending: the sliced path runs on delayed events, which stop when it's inactive.

## Blocking API

```csharp
public bool Verify(string data, string signatureHex)
public bool VerifyHash(byte[] hash32, string signatureHex)
```

`Verify` hashes `data` and checks the signature. `VerifyHash` checks a signature of a 32-byte hash you computed yourself. Both return `false` for any malformed input (null included) and never throw. Each call takes about 300 ms in the editor and 510 ms in the VRChat client, all in one frame, so the game freezes for that long. Use it in tests, tooling, or at moments where a hitch doesn't matter (for example while loading).

```csharp
using UdonSharp;
using UnityEngine;
using Secp256k1Udon;

public class BlockingExample : UdonSharpBehaviour
{
    public SignatureVerifier verifier;
    public string data;
    public string signatureHex;

    public void Check()
    {
        bool valid = verifier.Verify(data, signatureHex);
        Debug.Log(valid ? "signature valid" : "signature invalid");
    }
}
```

## Frame-sliced API

```csharp
public bool RequestVerify(string data, string signatureHex, UdonSharpBehaviour caller, string callbackEvent, int requestId)
```

This queues the request and returns `true`. The verifier works on it a little each frame. When it is done, the verifier:

1. sets its own public fields `resultRequestId` (`int`, the `requestId` you passed) and `resultValid` (`bool`),
2. then sends `callbackEvent` to `caller`.

Read the two fields through your verifier reference inside that event. The next result overwrites them.

- Requests run one at a time, in the order they were made, and each gets exactly one callback.
- Malformed input (null data, a bad signature, an invalid key) is accepted and reported invalid through the callback. A malformed signature is rejected in the first frame.
- `RequestVerify` returns `false` and never calls back when the queue is full (`queueCapacity` waiting requests), when `caller` is null, or when `callbackEvent` is null or empty. A full queue is not an error: try again later.
- The callback event must be a public method on `caller`. If `caller` was destroyed in the meantime, the callback is skipped.
- `PendingCount()` gives the number of requests waiting or running.
- After each request, `lastFrames`, `lastComputeMs` and `lastMaxFrameMs` hold the frames it took, its total computation time and its longest slice, in milliseconds.
- Calling the blocking `Verify` while a sliced request is running is safe; the two use separate buffers.
- `ProcessAllNow()` runs every pending request to completion in one call, callbacks included. It is meant for tests and tooling.

With the default `iterationsPerFrame` of 1, a request takes about 305 frames: about 5 s at 60 fps. Requests queued behind it wait their turn.

```csharp
using UdonSharp;
using UnityEngine;
using Secp256k1Udon;

public class SlicedExample : UdonSharpBehaviour
{
    public SignatureVerifier verifier;
    public string data;
    public string signatureHex;

    private int nextRequestId;

    public void Check()
    {
        int requestId = nextRequestId++;
        if (!verifier.RequestVerify(data, signatureHex, this, nameof(OnVerified), requestId))
        {
            Debug.Log("verifier queue full, try again later");
        }
    }

    // Called by the verifier when a request is done. Must be public.
    public void OnVerified()
    {
        Debug.Log("request " + verifier.resultRequestId + ": "
            + (verifier.resultValid ? "signature valid" : "signature invalid"));
    }
}
```

If you make several requests, use `resultRequestId` to tell which one finished.

## Nonces

```csharp
string nonce = NonceGenerator.NewNonce();
```

Returns a random version-4 UUID as a lowercase string in the 8-4-4-4-12 form, for example `bccee525-df6d-4611-9c88-7b56e31bf88c`. It uses `System.Guid.NewGuid()` (122 random bits) and never contains uppercase characters. It is a static method, so no behaviour or scene object is needed. 10,000 nonces in the tests had the right format and no duplicates.

## Performance

Measured on a desktop PC, Unity 2022.3.22f1 with the VRChat Worlds SDK 3.10.5. In the VRChat desktop client Udon ran about 1.6 times slower than in the editor's Play Mode.

| | Editor (Play Mode) | VRChat desktop client |
|---|---|---|
| Blocking `Verify` | about 290 ms | about 510 ms |
| `RequestVerify` at `iterationsPerFrame` 1: frames per verification | 303–306 | 303–306 |
| Average work per frame | about 1.0 ms | at most about 1.55 ms |
| Longest frame | about 1.3 ms, rarely up to 2.2 ms | 3.3 ms |
| `RequestVerify` at `iterationsPerFrame` 7 | 48 frames | 48 frames, about 9.5 ms per frame |

At 60 fps a sliced verification takes about 5 s, at 120 fps about 2.5 s. The first frame of a request also encodes the data as UTF-8, which adds about 0.6 ms per 1,000 characters, and hashing adds a few frames for long data (four 64-byte blocks per frame).

## Using it in another project

Copy the library folder into your project's `Assets`, **without** its `Tests` folder:

- `Assets/Secp256k1Udon/*.cs` and their `.meta` files
- `Assets/Secp256k1Udon/Secp256k1Udon.asmdef` (the assembly definition) and `Secp256k1Udon.asset` (its UdonSharp assembly definition), with their `.meta` files
- `Assets/Secp256k1Udon/SignatureVerifier.asset` (the UdonSharp program asset for `SignatureVerifier`), with its `.meta` file
- this `README.md`, if you like

Do not copy `Assets/Secp256k1Udon/Tests/` or the repository's `Tools/` folder; the library doesn't use them. The only requirements are the VRChat Worlds SDK (3.10.5 was used here) with its bundled UdonSharp.

Because the library has its own assembly definition, scripts that use it must be in an assembly that can see it. Scripts in the default `Assembly-CSharp` (no assembly definition of their own) see it automatically. If your scripts have their own assembly definition, add `Secp256k1Udon` to its references.

Everything is in the `Secp256k1Udon` namespace. Besides `SignatureVerifier` and `NonceGenerator`, the static classes `Sha256`, `Utf8`, `Hex`, `U256` and `Secp256k1` are public too, if you need SHA-256, UTF-8 or hex on their own. They allocate nothing per call and take caller-owned scratch buffers (see the comments in each file).
