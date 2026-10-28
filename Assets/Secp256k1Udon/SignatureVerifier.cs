using UdonSharp;
using UnityEngine;

namespace Secp256k1Udon
{
    // Verifies that a string was signed by the authority whose public key is set in the inspector:
    // ECDSA over secp256k1 of SHA-256(UTF-8 bytes of data), with the signature as 130 hex chars r || s || v
    // (either case; v is ignored). The data is opaque: it is hashed, never parsed.
    //
    // The key is validated once, at Start or on first use, whichever comes first. An invalid key logs an
    // error and makes every verification return false.
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class SignatureVerifier : UdonSharpBehaviour
    {
        [Tooltip("Authority public key, uncompressed: 04 || x || y as 130 hex characters (either case).")]
        public string publicKeyHex;

        private bool initialized;
        private bool keyValid;
        private uint[] key;
        private uint[] curveScratch;
        private ulong[] product;
        private uint[] shaScratch;
        private byte[] hash;

        private void Start()
        {
            Initialize();
        }

        public bool IsKeyValid()
        {
            Initialize();
            return keyValid;
        }

        // Blocking verification of data against signatureHex. Takes a long frame; see the frame-sliced API for
        // calls during play. Returns false for any malformed input (null included) and never throws.
        public bool Verify(string data, string signatureHex)
        {
            Initialize();
            if (!keyValid || data == null) return false;
            Sha256.Hash(Utf8.Encode(data), shaScratch, hash, 0);
            return Secp256k1.VerifyHash(hash, 0, signatureHex, key, 0, curveScratch, product);
        }

        // Blocking verification of a precomputed 32-byte message hash, used directly as z.
        public bool VerifyHash(byte[] hash32, string signatureHex)
        {
            Initialize();
            if (!keyValid || hash32 == null || hash32.Length != 32) return false;
            return Secp256k1.VerifyHash(hash32, 0, signatureHex, key, 0, curveScratch, product);
        }

        private void Initialize()
        {
            if (initialized) return;
            initialized = true;
            key = new uint[Secp256k1.AffineLength];
            curveScratch = Secp256k1.NewScratch();
            product = new ulong[U256.ProductScratchLength];
            shaScratch = Sha256.NewScratch();
            hash = new byte[32];
            keyValid = Secp256k1.LoadPublicKey(publicKeyHex, key, 0, curveScratch, product);
            if (!keyValid)
            {
                Debug.LogError("[SignatureVerifier] invalid public key on " + gameObject.name
                    + " (expected 04 || x || y as 130 hex characters, a point on secp256k1); every verification will fail");
            }
        }
    }
}
