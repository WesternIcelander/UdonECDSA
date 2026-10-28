namespace Secp256k1Udon
{
    // Point arithmetic on secp256k1 (y² = x³ + 7 over the field mod p).
    //
    // A Jacobian point is 24 limbs at an offset: X at [0..7], Y at [8..15], Z at [16..23], standing for the
    // affine point (X/Z², Y/Z³); Z = 0 is the point at infinity. An affine point is 16 limbs: x, then y (it
    // cannot be infinity). Coordinates are canonical field elements (U256 conventions).
    //
    // Static classes cannot hold fields in Udon, so the caller owns the working buffer: allocate it once
    // with NewScratch() (which also holds G) and pass it, with a ulong[U256.ProductScratchLength], to every
    // call. Results may alias the inputs, but no input or result may lie inside the scratch's temporaries
    // ([0..TempLength-1]); the double-multiplication table and accumulator are fine as inputs.
    public static class Secp256k1
    {
        public const int PointLength = 24;
        public const int AffineLength = 16;

        // Scratch layout: 12 field temporaries, then G (affine), Q (affine), G + Q and the accumulator
        // (Jacobian) of the double multiplication, then the verification scalars: r, s, u1, u2 and one temporary.
        private const int TempLength = 96;
        public const int GOffset = 96;
        public const int QOffset = 112;
        private const int GQOffset = 128;
        public const int AccumulatorOffset = 152;
        public const int ROffset = 176;
        public const int SOffset = 184;
        public const int U1Offset = 192;
        public const int U2Offset = 200;
        private const int VerifyTemp = 208;
        public const int ScratchLength = 216;

        public const int SignatureHexLength = 130;

        private const int T0 = 0;
        private const int T1 = 8;
        private const int T2 = 16;
        private const int T3 = 24;
        private const int T4 = 32;
        private const int T5 = 40;
        private const int T6 = 48;
        private const int T7 = 56;
        private const int T8 = 64;
        private const int T9 = 72;
        private const int T10 = 80;
        private const int T11 = 88;

        public static uint[] NewScratch()
        {
            uint[] s = new uint[ScratchLength];
            // Gx = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
            s[GOffset + 7] = 0x79BE667Eu;
            s[GOffset + 6] = 0xF9DCBBACu;
            s[GOffset + 5] = 0x55A06295u;
            s[GOffset + 4] = 0xCE870B07u;
            s[GOffset + 3] = 0x029BFCDBu;
            s[GOffset + 2] = 0x2DCE28D9u;
            s[GOffset + 1] = 0x59F2815Bu;
            s[GOffset + 0] = 0x16F81798u;
            // Gy = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
            s[GOffset + 15] = 0x483ADA77u;
            s[GOffset + 14] = 0x26A3C465u;
            s[GOffset + 13] = 0x5DA4FBFCu;
            s[GOffset + 12] = 0x0E1108A8u;
            s[GOffset + 11] = 0xFD17B448u;
            s[GOffset + 10] = 0xA6855419u;
            s[GOffset + 9] = 0x9C47D08Fu;
            s[GOffset + 8] = 0xFB10D4B8u;
            return s;
        }

        public static void SetInfinity(uint[] r, int ro)
        {
            for (int i = 0; i < PointLength; i++) r[ro + i] = 0u;
        }

        public static bool IsInfinity(uint[] p, int po)
        {
            return U256.IsZero(p, po + 16);
        }

        // Affine (x, y) -> Jacobian (x, y, 1).
        public static void FromAffine(uint[] a, int ao, uint[] r, int ro)
        {
            U256.Copy(a, ao, r, ro);
            U256.Copy(a, ao + 8, r, ro + 8);
            for (int i = 1; i < 8; i++) r[ro + 16 + i] = 0u;
            r[ro + 16] = 1u;
        }

        // Jacobian -> affine, with a field inverse (slow; for tests and debugging, not for verification).
        // Returns false, leaving r alone, for the point at infinity.
        public static bool ToAffine(uint[] p, int po, uint[] r, int ro, uint[] s, ulong[] t)
        {
            if (IsInfinity(p, po)) return false;
            U256.FieldInv(p, po + 16, s, T0, s, T1, t);
            U256.FieldSqr(s, T0, s, T2, t);
            U256.FieldMul(s, T2, s, T0, s, T3, t);
            U256.FieldMul(p, po, s, T2, s, T4, t);
            U256.FieldMul(p, po + 8, s, T3, r, ro + 8, t);
            U256.Copy(s, T4, r, ro);
            return true;
        }

        // r = 2P, for a = 0 (dbl-2009-l, 2M + 5S). Points of order 2 do not exist on secp256k1, so Y = 0
        // never occurs for a finite point.
        public static void Double(uint[] p, int po, uint[] r, int ro, uint[] s, ulong[] t)
        {
            if (IsInfinity(p, po))
            {
                SetInfinity(r, ro);
                return;
            }
            U256.FieldSqr(p, po, s, T0, t);                 // A = X²
            U256.FieldSqr(p, po + 8, s, T1, t);             // B = Y²
            U256.FieldSqr(s, T1, s, T2, t);                 // C = B²
            U256.FieldAdd(p, po, s, T1, s, T3);
            U256.FieldSqr(s, T3, s, T3, t);
            U256.FieldSub(s, T3, s, T0, s, T3);
            U256.FieldSub(s, T3, s, T2, s, T3);
            U256.FieldAdd(s, T3, s, T3, s, T3);             // D = 2((X + B)² - A - C)
            U256.FieldAdd(s, T0, s, T0, s, T4);
            U256.FieldAdd(s, T4, s, T0, s, T4);             // E = 3A
            U256.FieldSqr(s, T4, s, T5, t);                 // F = E²
            U256.FieldAdd(s, T3, s, T3, s, T6);
            U256.FieldSub(s, T5, s, T6, s, T6);             // X3 = F - 2D
            U256.FieldMul(p, po + 8, p, po + 16, s, T8, t);
            U256.FieldAdd(s, T8, s, T8, s, T8);             // Z3 = 2YZ
            U256.FieldSub(s, T3, s, T6, s, T7);
            U256.FieldMul(s, T4, s, T7, s, T7, t);
            U256.FieldAdd(s, T2, s, T2, s, T2);
            U256.FieldAdd(s, T2, s, T2, s, T2);
            U256.FieldAdd(s, T2, s, T2, s, T2);
            U256.FieldSub(s, T7, s, T2, s, T7);             // Y3 = E(D - X3) - 8C
            U256.Copy(s, T6, r, ro);
            U256.Copy(s, T7, r, ro + 8);
            U256.Copy(s, T8, r, ro + 16);
        }

        // r = P + Q, both Jacobian (12M + 4S). Handles infinity on either side, P == Q and P == -Q.
        public static void Add(uint[] p, int po, uint[] q, int qo, uint[] r, int ro, uint[] s, ulong[] t)
        {
            if (IsInfinity(q, qo))
            {
                CopyPoint(p, po, r, ro);
                return;
            }
            AddCore(p, po, q, qo, false, r, ro, s, t);
        }

        // r = P + Q, P Jacobian and Q affine (mixed addition, 8M + 3S). Handles P at infinity, P == Q and
        // P == -Q.
        public static void AddAffine(uint[] p, int po, uint[] q, int qo, uint[] r, int ro, uint[] s, ulong[] t)
        {
            AddCore(p, po, q, qo, true, r, ro, s, t);
        }

        // add-2007-bl, with the Z2 = 1 shortcuts when Q is affine. Q is finite here.
        private static void AddCore(uint[] p, int po, uint[] q, int qo, bool qAffine, uint[] r, int ro, uint[] s, ulong[] t)
        {
            if (IsInfinity(p, po))
            {
                if (qAffine) FromAffine(q, qo, r, ro);
                else CopyPoint(q, qo, r, ro);
                return;
            }
            U256.FieldSqr(p, po + 16, s, T0, t);                        // Z1Z1 = Z1²
            U256.FieldMul(q, qo, s, T0, s, T3, t);                      // U2 = X2·Z1Z1
            U256.FieldMul(q, qo + 8, p, po + 16, s, T5, t);
            U256.FieldMul(s, T5, s, T0, s, T5, t);                      // S2 = Y2·Z1·Z1Z1
            if (qAffine)
            {
                U256.Copy(p, po, s, T2);                                // U1 = X1
                U256.Copy(p, po + 8, s, T4);                            // S1 = Y1
            }
            else
            {
                U256.FieldSqr(q, qo + 16, s, T1, t);                    // Z2Z2 = Z2²
                U256.FieldMul(p, po, s, T1, s, T2, t);                  // U1 = X1·Z2Z2
                U256.FieldMul(p, po + 8, q, qo + 16, s, T4, t);
                U256.FieldMul(s, T4, s, T1, s, T4, t);                  // S1 = Y1·Z2·Z2Z2
            }
            U256.FieldSub(s, T3, s, T2, s, T6);                         // H = U2 - U1
            U256.FieldSub(s, T5, s, T4, s, T7);                         // R = S2 - S1
            if (U256.IsZero(s, T6))
            {
                if (U256.IsZero(s, T7)) Double(p, po, r, ro, s, t);    // P == Q
                else SetInfinity(r, ro);                                // P == -Q
                return;
            }
            // Z3 = Z1·Z2·H, while P and Q are still intact.
            U256.FieldMul(p, po + 16, s, T6, s, T5, t);
            if (!qAffine) U256.FieldMul(s, T5, q, qo + 16, s, T5, t);
            U256.FieldSqr(s, T6, s, T8, t);                             // HH = H²
            U256.FieldMul(s, T6, s, T8, s, T9, t);                      // HHH = H·HH
            U256.FieldMul(s, T2, s, T8, s, T10, t);                     // V = U1·HH
            U256.FieldSqr(s, T7, s, T11, t);
            U256.FieldSub(s, T11, s, T9, s, T11);
            U256.FieldSub(s, T11, s, T10, s, T11);
            U256.FieldSub(s, T11, s, T10, s, T11);                      // X3 = R² - HHH - 2V
            U256.FieldSub(s, T10, s, T11, s, T3);
            U256.FieldMul(s, T7, s, T3, s, T3, t);
            U256.FieldMul(s, T4, s, T9, s, T0, t);
            U256.FieldSub(s, T3, s, T0, s, T3);                         // Y3 = R(V - X3) - S1·HHH
            U256.Copy(s, T11, r, ro);
            U256.Copy(s, T3, r, ro + 8);
            U256.Copy(s, T5, r, ro + 16);
        }

        public static void CopyPoint(uint[] p, int po, uint[] r, int ro)
        {
            for (int i = 0; i < PointLength; i++) r[ro + i] = p[po + i];
        }

        // r = u1·G + u2·Q (Shamir's trick: one shared double-and-add loop over 256 bits, adding G, Q or
        // G + Q). u1 and u2 are any 256-bit values; Q is affine.
        public static void DoubleMul(uint[] u1, int u1o, uint[] u2, int u2o, uint[] q, int qo, uint[] r, int ro, uint[] s, ulong[] t)
        {
            DoubleMulInit(q, qo, s, t);
            DoubleMulBits(u1, u1o, u2, u2o, 255, 256, s, t);
            CopyPoint(s, AccumulatorOffset, r, ro);
        }

        // Start of a double multiplication that can be run in slices: stores Q, precomputes G + Q and sets
        // the accumulator (at AccumulatorOffset in the scratch) to infinity.
        public static void DoubleMulInit(uint[] q, int qo, uint[] s, ulong[] t)
        {
            U256.Copy(q, qo, s, QOffset);
            U256.Copy(q, qo + 8, s, QOffset + 8);
            FromAffine(s, GOffset, s, GQOffset);
            AddAffine(s, GQOffset, s, QOffset, s, GQOffset, s, t);
            SetInfinity(s, AccumulatorOffset);
        }

        // Processes count bits of u1 and u2, from bit `fromBit` downwards, into the accumulator. A full run is
        // fromBit 255 and count 256, in as many slices as wanted.
        public static void DoubleMulBits(uint[] u1, int u1o, uint[] u2, int u2o, int fromBit, int count, uint[] s, ulong[] t)
        {
            for (int bit = fromBit; bit > fromBit - count; bit--)
            {
                Double(s, AccumulatorOffset, s, AccumulatorOffset, s, t);
                int limb = bit >> 5;
                int shift = bit & 31;
                bool b1 = ((u1[u1o + limb] >> shift) & 1u) != 0u;
                bool b2 = ((u2[u2o + limb] >> shift) & 1u) != 0u;
                if (b1 && b2) Add(s, AccumulatorOffset, s, GQOffset, s, AccumulatorOffset, s, t);
                else if (b1) AddAffine(s, AccumulatorOffset, s, GOffset, s, AccumulatorOffset, s, t);
                else if (b2) AddAffine(s, AccumulatorOffset, s, QOffset, s, AccumulatorOffset, s, t);
            }
        }

        // ECDSA verification of a 32-byte message hash at hash[ho..] (used directly as z, reduced mod n) against
        // signatureHex and the affine public key at q[qo..] (from LoadPublicKey). The signature is 130 hex chars,
        // either case: r || s || v, with v ignored (but still required to be hex). High s is accepted. Returns
        // false for any malformed or invalid input and never throws. Allocates nothing.
        //
        // The steps are public so the frame-sliced verifier can spread them over frames: VerifyParse, VerifySetup
        // (itself VerifySetupBegin, VerifyInverseBits over 255, 256 in slices, VerifySetupEnd),
        // DoubleMulBits(s, U1Offset, s, U2Offset, 255, 256 in slices) and VerifyFinish.
        public static bool VerifyHash(byte[] hash, int ho, string signatureHex, uint[] q, int qo, uint[] s, ulong[] t)
        {
            if (hash == null || ho < 0 || hash.Length - ho < 32) return false;
            if (!VerifyParse(signatureHex, s)) return false;
            VerifySetup(hash, ho, q, qo, s, t);
            DoubleMulBits(s, U1Offset, s, U2Offset, 255, 256, s, t);
            return VerifyFinish(s, t);
        }

        // Parses the signature into r and s (at ROffset and SOffset) and checks 1 <= r, s <= n - 1. Returns false
        // for a null signature, a length other than 130, any non-hex character (v included) or r, s out of range.
        public static bool VerifyParse(string signatureHex, uint[] s)
        {
            if (signatureHex == null || signatureHex.Length != SignatureHexLength) return false;
            if (!Hex.DecodeLimbs(signatureHex, 0, s, ROffset)) return false;
            if (!Hex.DecodeLimbs(signatureHex, 64, s, SOffset)) return false;
            if (!Hex.IsHex(signatureHex, 128, 2)) return false;
            if (U256.IsZero(s, ROffset) || U256.ScalarGeN(s, ROffset)) return false;
            if (U256.IsZero(s, SOffset) || U256.ScalarGeN(s, SOffset)) return false;
            return true;
        }

        // After VerifyParse: z = hash mod n, w = s⁻¹, u1 = z·w and u2 = r·w (mod n), then DoubleMulInit with Q.
        // hash[ho..ho+31] must exist.
        public static void VerifySetup(byte[] hash, int ho, uint[] q, int qo, uint[] s, ulong[] t)
        {
            VerifySetupBegin(hash, ho, s);
            VerifyInverseBits(255, 256, s, t);
            VerifySetupEnd(q, qo, s, t);
        }

        // VerifySetup in slices: VerifySetupBegin (z, start of w = s⁻¹), VerifyInverseBits over bits 255 down to 0,
        // then VerifySetupEnd (u1, u2, DoubleMulInit).
        public static void VerifySetupBegin(byte[] hash, int ho, uint[] s)
        {
            U256.FromBytes(hash, ho, s, U1Offset);
            U256.ScalarReduce(s, U1Offset);                                 // z
            U256.ScalarInvBegin(s, SOffset, s, U2Offset, s, VerifyTemp);
        }

        public static void VerifyInverseBits(int fromBit, int count, uint[] s, ulong[] t)
        {
            U256.ScalarInvBits(s, U2Offset, s, VerifyTemp, fromBit, count, t);   // w
        }

        public static void VerifySetupEnd(uint[] q, int qo, uint[] s, ulong[] t)
        {
            U256.ScalarMul(s, U1Offset, s, U2Offset, s, U1Offset, t);       // u1 = z·w
            U256.ScalarMul(s, ROffset, s, U2Offset, s, U2Offset, t);        // u2 = r·w
            DoubleMulInit(q, qo, s, t);
        }

        // After the double multiplication: R = u1·G + u2·Q is in the accumulator. Accepts if R is finite and its
        // affine x is r or r + n (the x coordinates that reduce to r mod n), compared without inverting:
        // x = X/Z², so test r·Z² ≡ X (mod p), and (r + n)·Z² ≡ X when r + n < p.
        public static bool VerifyFinish(uint[] s, ulong[] t)
        {
            if (IsInfinity(s, AccumulatorOffset)) return false;
            U256.FieldSqr(s, AccumulatorOffset + 16, s, T0, t);             // Z²
            U256.FieldMul(s, ROffset, s, T0, s, T1, t);
            if (U256.Compare(s, T1, s, AccumulatorOffset) == 0) return true;
            if (!U256.AddN(s, ROffset, s, VerifyTemp) || U256.FieldGeP(s, VerifyTemp)) return false;
            U256.FieldMul(s, VerifyTemp, s, T0, s, T1, t);
            return U256.Compare(s, T1, s, AccumulatorOffset) == 0;
        }

        // Parses and validates an uncompressed public key (130 hex chars, either case: 04 || x || y) into the
        // affine point at r[ro..ro+15]. Checks the prefix, x and y below p, and y² = x³ + 7. Returns false,
        // leaving r alone, for any malformed or invalid key. Allocates (hex decoding); run it once per key.
        public static bool LoadPublicKey(string hex, uint[] r, int ro, uint[] s, ulong[] t)
        {
            if (hex == null || hex.Length != 130) return false;
            byte[] bytes = Hex.Decode(hex);
            if (bytes == null || bytes[0] != 0x04) return false;
            U256.FromBytes(bytes, 1, s, T0);
            U256.FromBytes(bytes, 33, s, T1);
            if (U256.FieldGeP(s, T0) || U256.FieldGeP(s, T1)) return false;
            U256.FieldSqr(s, T1, s, T2, t);                 // y²
            U256.FieldSqr(s, T0, s, T3, t);
            U256.FieldMul(s, T3, s, T0, s, T3, t);
            for (int i = 1; i < 8; i++) s[T4 + i] = 0u;
            s[T4] = 7u;
            U256.FieldAdd(s, T3, s, T4, s, T3);             // x³ + 7
            if (U256.Compare(s, T2, s, T3) != 0) return false;
            U256.Copy(s, T0, r, ro);
            U256.Copy(s, T1, r, ro + 8);
            return true;
        }
    }
}
