using System;

namespace Secp256k1Udon
{
    // Random nonces as lowercase UUID-style strings (8-4-4-4-12 hex), from System.Guid.NewGuid(), which is
    // exposed to Udon and gives a random version-4 UUID in the lowercase "D" format.
    public static class NonceGenerator
    {
        public static string NewNonce()
        {
            // Already lowercase; ToLowerInvariant guarantees it should a runtime ever format otherwise.
            return Guid.NewGuid().ToString().ToLowerInvariant();
        }
    }
}
