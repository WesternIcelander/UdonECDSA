namespace Secp256k1Udon
{
    // 256-bit numbers as 8 x 32-bit limbs in a uint[] at an offset, least significant limb first.
    //
    // Field arithmetic mod p = 2^256 - 2^32 - 977. Inputs must be canonical (below p) unless stated
    // otherwise, and results are canonical. The result may alias either input. Static classes cannot hold
    // fields in Udon, so multiply, square and inverse take a caller-owned ulong[ProductScratchLength]
    // (allocate once and reuse; nothing here allocates).
    //
    // Scalar arithmetic mod n (the group order) follows the same conventions, but multiply, square and
    // inverse accept any 256-bit inputs. Results are canonical (below n).
    public static class U256
    {
        public const int ProductScratchLength = 32;

        private const ulong Mask32 = 0xFFFFFFFFUL;
        // 2^256 mod p = 2^32 + 977.
        private const ulong FoldLow = 977UL;

        // Product scratch layout: 16-limb product at [0..15], operand a at [16..23], operand b at [24..31].
        private const int ScratchA = 16;
        private const int ScratchB = 24;

        public static void Copy(uint[] a, int ao, uint[] r, int ro)
        {
            for (int i = 0; i < 8; i++) r[ro + i] = a[ao + i];
        }

        public static bool IsZero(uint[] a, int ao)
        {
            for (int i = 0; i < 8; i++)
            {
                if (a[ao + i] != 0u) return false;
            }
            return true;
        }

        // -1, 0 or 1 as a is below, equal to or above b (plain 256-bit compare).
        public static int Compare(uint[] a, int ao, uint[] b, int bo)
        {
            for (int i = 7; i >= 0; i--)
            {
                uint x = a[ao + i];
                uint y = b[bo + i];
                if (x != y) return x < y ? -1 : 1;
            }
            return 0;
        }

        // a >= p, for any 256-bit a.
        public static bool FieldGeP(uint[] a, int ao)
        {
            for (int i = 7; i >= 2; i--)
            {
                if (a[ao + i] != 0xFFFFFFFFu) return false;
            }
            uint a1 = a[ao + 1];
            if (a1 != 0xFFFFFFFEu) return a1 > 0xFFFFFFFEu;
            return a[ao] >= 0xFFFFFC2Fu;
        }

        // Conditional subtract: reduces any 256-bit a (in place) to a mod p. One subtract suffices since 2^256 < 2p.
        public static void FieldReduce(uint[] a, int ao)
        {
            if (FieldGeP(a, ao)) AddFold(a, ao);
        }

        public static void FieldAdd(uint[] a, int ao, uint[] b, int bo, uint[] r, int ro)
        {
            ulong carry = 0;
            for (int i = 0; i < 8; i++)
            {
                ulong v = (ulong)a[ao + i] + b[bo + i] + carry;
                r[ro + i] = (uint)(v & Mask32);
                carry = v >> 32;
            }
            // The sum is below 2p: subtract p once if it overflowed 2^256 or is at least p.
            if (carry != 0 || FieldGeP(r, ro)) AddFold(r, ro);
        }

        public static void FieldSub(uint[] a, int ao, uint[] b, int bo, uint[] r, int ro)
        {
            ulong borrow = 0;
            for (int i = 0; i < 8; i++)
            {
                ulong v = (ulong)a[ao + i] - b[bo + i] - borrow;
                r[ro + i] = (uint)(v & Mask32);
                borrow = v >> 63;
            }
            // Wrapped to a - b + 2^256; adding p instead means subtracting 2^32 + 977.
            if (borrow != 0) SubFold(r, ro);
        }

        public static void FieldMul(uint[] a, int ao, uint[] b, int bo, uint[] r, int ro, ulong[] t)
        {
            Product(a, ao, b, bo, t);
            ReduceProduct(t, r, ro);
        }

        public static void FieldSqr(uint[] a, int ao, uint[] r, int ro, ulong[] t)
        {
            SquareProduct(a, ao, t);
            ReduceProduct(t, r, ro);
        }

        // 16-limb product a·b into t[0..15]. Operands are copied first, so they may alias anything.
        private static void Product(uint[] a, int ao, uint[] b, int bo, ulong[] t)
        {
            for (int i = 0; i < 8; i++)
            {
                t[ScratchA + i] = a[ao + i];
                t[ScratchB + i] = b[bo + i];
                t[i] = 0;
            }
            // Schoolbook product; t[i + 8] is written before row i + 1 reads it.
            for (int i = 0; i < 8; i++)
            {
                ulong ai = t[ScratchA + i];
                ulong carry = 0;
                for (int j = 0; j < 8; j++)
                {
                    ulong v = t[i + j] + ai * t[ScratchB + j] + carry;
                    t[i + j] = v & Mask32;
                    carry = v >> 32;
                }
                t[i + 8] = carry;
            }
        }

        // 16-limb square a² into t[0..15], computing each cross product once (36 limb products instead of 64).
        private static void SquareProduct(uint[] a, int ao, ulong[] t)
        {
            for (int i = 0; i < 8; i++) t[ScratchA + i] = a[ao + i];
            for (int i = 0; i < 16; i++) t[i] = 0;
            // Cross products a[i]·a[j] for i < j, once each.
            for (int i = 0; i < 7; i++)
            {
                ulong ai = t[ScratchA + i];
                ulong carry = 0;
                for (int j = i + 1; j < 8; j++)
                {
                    ulong v = t[i + j] + ai * t[ScratchA + j] + carry;
                    t[i + j] = v & Mask32;
                    carry = v >> 32;
                }
                t[i + 8] = carry;
            }
            // Double the cross products and add the squares a[i]² at limb 2i.
            ulong c = 0;
            for (int i = 0; i < 8; i++)
            {
                ulong ai = t[ScratchA + i];
                ulong sq = ai * ai;
                int k = 2 * i;
                ulong v = (t[k] << 1) + (sq & Mask32) + c;
                t[k] = v & Mask32;
                c = v >> 32;
                v = (t[k + 1] << 1) + (sq >> 32) + c;
                t[k + 1] = v & Mask32;
                c = v >> 32;
            }
        }

        // r = a^(p-2) = a⁻¹ mod p (0 for a = 0). Slow (about 256 squares and multiplies); verification does
        // not use it, it is for tests and debugging in affine coordinates. tmp[to..to+7] holds a copy of a.
        public static void FieldInv(uint[] a, int ao, uint[] r, int ro, uint[] tmp, int to, ulong[] t)
        {
            Copy(a, ao, tmp, to);
            for (int i = 1; i < 8; i++) r[ro + i] = 0u;
            r[ro] = 1u;
            for (int bit = 255; bit >= 0; bit--)
            {
                FieldSqr(r, ro, r, ro, t);
                int limb = bit >> 5;
                // p - 2 = FFFFFFFF x 6, FFFFFFFE, FFFFFC2D (most significant limb first).
                uint e = limb >= 2 ? 0xFFFFFFFFu : (limb == 1 ? 0xFFFFFFFEu : 0xFFFFFC2Du);
                if (((e >> (bit & 31)) & 1u) != 0u) FieldMul(r, ro, tmp, to, r, ro, t);
            }
        }

        // Reduces the 16-limb product in t[0..15] mod p into r, using 2^256 ≡ 2^32 + 977.
        private static void ReduceProduct(ulong[] t, uint[] r, int ro)
        {
            // First fold: low + high·(2^32 + 977) into t[0..7] plus a top word below 2^34.
            ulong v = t[0] + t[8] * FoldLow;
            t[0] = v & Mask32;
            ulong carry = v >> 32;
            for (int i = 1; i < 8; i++)
            {
                v = t[i] + t[8 + i] * FoldLow + t[7 + i] + carry;
                t[i] = v & Mask32;
                carry = v >> 32;
            }
            ulong top = t[15] + carry;

            // Second fold: top·(2^32 + 977).
            v = t[0] + top * FoldLow;
            r[ro] = (uint)(v & Mask32);
            v = t[1] + top + (v >> 32);
            r[ro + 1] = (uint)(v & Mask32);
            carry = v >> 32;
            for (int i = 2; i < 8; i++)
            {
                v = t[i] + carry;
                r[ro + i] = (uint)(v & Mask32);
                carry = v >> 32;
            }
            // Overflowing 2^256 leaves a small value, so folding the carry once more cannot overflow again.
            if (carry != 0) AddFold(r, ro);
            if (FieldGeP(r, ro)) AddFold(r, ro);
        }

        // a += 2^32 + 977 mod 2^256, in place (subtracts p when a + 2^32 + 977 crosses 2^256).
        private static void AddFold(uint[] a, int ao)
        {
            ulong v = (ulong)a[ao] + FoldLow;
            a[ao] = (uint)(v & Mask32);
            v = (ulong)a[ao + 1] + 1UL + (v >> 32);
            a[ao + 1] = (uint)(v & Mask32);
            ulong carry = v >> 32;
            for (int i = 2; i < 8 && carry != 0; i++)
            {
                v = (ulong)a[ao + i] + carry;
                a[ao + i] = (uint)(v & Mask32);
                carry = v >> 32;
            }
        }

        // a -= 2^32 + 977 mod 2^256, in place (adds p when a had wrapped past 2^256).
        private static void SubFold(uint[] a, int ao)
        {
            ulong v = (ulong)a[ao] - FoldLow;
            a[ao] = (uint)(v & Mask32);
            v = (ulong)a[ao + 1] - 1UL - (v >> 63);
            a[ao + 1] = (uint)(v & Mask32);
            ulong borrow = v >> 63;
            for (int i = 2; i < 8 && borrow != 0; i++)
            {
                v = (ulong)a[ao + i] - borrow;
                a[ao + i] = (uint)(v & Mask32);
                borrow = v >> 63;
            }
        }

        // Limbs 0..3 of 2^256 - n (129 bits; limb 4 is 1).
        private const ulong NC0 = 0x2FC9BEBFUL;
        private const ulong NC1 = 0x402DA173UL;
        private const ulong NC2 = 0x50B75FC4UL;
        private const ulong NC3 = 0x45512319UL;

        // Limb i of n.
        private static uint NLimb(int i)
        {
            if (i >= 5) return 0xFFFFFFFFu;
            if (i == 4) return 0xFFFFFFFEu;
            if (i == 3) return 0xBAAEDCE6u;
            if (i == 2) return 0xAF48A03Bu;
            if (i == 1) return 0xBFD25E8Cu;
            return 0xD0364141u;
        }

        // a >= n, for any 256-bit a.
        public static bool ScalarGeN(uint[] a, int ao)
        {
            for (int i = 7; i >= 0; i--)
            {
                uint x = a[ao + i];
                uint y = NLimb(i);
                if (x != y) return x > y;
            }
            return true;
        }

        // r = a + n. Returns false, with r holding the sum mod 2^256, if the sum reaches 2^256. r may alias a.
        public static bool AddN(uint[] a, int ao, uint[] r, int ro)
        {
            ulong carry = 0;
            for (int i = 0; i < 8; i++)
            {
                ulong v = (ulong)a[ao + i] + NLimb(i) + carry;
                r[ro + i] = (uint)(v & Mask32);
                carry = v >> 32;
            }
            return carry == 0;
        }

        // Reduces any 256-bit a (in place) to a mod n. One subtract suffices since 2^256 < 2n.
        public static void ScalarReduce(uint[] a, int ao)
        {
            if (ScalarGeN(a, ao)) AddNC(a, ao);
        }

        // r = a·b mod n, for any 256-bit a and b (they need not be below n).
        public static void ScalarMul(uint[] a, int ao, uint[] b, int bo, uint[] r, int ro, ulong[] t)
        {
            Product(a, ao, b, bo, t);
            ReduceProductN(t, r, ro);
        }

        public static void ScalarSqr(uint[] a, int ao, uint[] r, int ro, ulong[] t)
        {
            SquareProduct(a, ao, t);
            ReduceProductN(t, r, ro);
        }

        // r = a^(n-2) = a⁻¹ mod n (0 for a ≡ 0), for any 256-bit a. About 256 squares and 200 multiplies;
        // runs once per verification (w = s⁻¹). tmp[to..to+7] holds a copy of a.
        public static void ScalarInv(uint[] a, int ao, uint[] r, int ro, uint[] tmp, int to, ulong[] t)
        {
            ScalarInvBegin(a, ao, r, ro, tmp, to);
            ScalarInvBits(r, ro, tmp, to, 255, 256, t);
        }

        // ScalarInv in slices: ScalarInvBegin, then ScalarInvBits over bits 255 down to 0 in as many calls as
        // wanted (a full run is fromBit 255 and count 256). r and tmp hold the state in between.
        public static void ScalarInvBegin(uint[] a, int ao, uint[] r, int ro, uint[] tmp, int to)
        {
            Copy(a, ao, tmp, to);
            for (int i = 1; i < 8; i++) r[ro + i] = 0u;
            r[ro] = 1u;
        }

        // Processes count bits of the exponent n - 2, from bit `fromBit` downwards.
        public static void ScalarInvBits(uint[] r, int ro, uint[] tmp, int to, int fromBit, int count, ulong[] t)
        {
            for (int bit = fromBit; bit > fromBit - count; bit--)
            {
                ScalarSqr(r, ro, r, ro, t);
                int limb = bit >> 5;
                // n - 2 differs from n only in limb 0.
                uint e = limb == 0 ? 0xD036413Fu : NLimb(limb);
                if (((e >> (bit & 31)) & 1u) != 0u) ScalarMul(r, ro, tmp, to, r, ro, t);
            }
        }

        // Reduces the 16-limb product in t[0..15] mod n into r, using 2^256 ≡ 2^256 - n (mod n). Each fold
        // replaces the part above 2^256 by its product with 2^256 - n: 512 -> 386 -> 260 -> 257 -> 256 bits.
        private static void ReduceProductN(ulong[] t, uint[] r, int ro)
        {
            FoldN(t, 0, 8, 16, 13);
            FoldN(t, 16, 5, 0, 9);
            FoldN(t, 0, 1, 16, 9);
            // The value is now below 2^256 + 2^134: if limb 8 is set, the low part is below 2^134, so this
            // last fold cannot carry past 2^256.
            FoldN(t, 16, 1, 0, 9);
            for (int i = 0; i < 8; i++) r[ro + i] = (uint)(t[i] & Mask32);
            if (ScalarGeN(r, ro)) AddNC(r, ro);
        }

        // t[dst..dst+len-1] = t[src..src+7] + t[src+8..src+8+highLen-1]·(2^256 - n). The ranges must not
        // overlap, and len must be large enough to hold the sum (the caller's bounds guarantee no carry out).
        private static void FoldN(ulong[] t, int src, int highLen, int dst, int len)
        {
            for (int k = 0; k < len; k++) t[dst + k] = k < 8 ? t[src + k] : 0UL;
            for (int i = 0; i < highLen; i++)
            {
                ulong h = t[src + 8 + i];
                if (h == 0UL) continue;
                int d = dst + i;
                ulong v = t[d] + h * NC0;
                t[d] = v & Mask32;
                v = t[d + 1] + h * NC1 + (v >> 32);
                t[d + 1] = v & Mask32;
                v = t[d + 2] + h * NC2 + (v >> 32);
                t[d + 2] = v & Mask32;
                v = t[d + 3] + h * NC3 + (v >> 32);
                t[d + 3] = v & Mask32;
                v = t[d + 4] + h + (v >> 32);
                t[d + 4] = v & Mask32;
                ulong carry = v >> 32;
                for (int k = d + 5; carry != 0; k++)
                {
                    v = t[k] + carry;
                    t[k] = v & Mask32;
                    carry = v >> 32;
                }
            }
        }

        // a += 2^256 - n mod 2^256, in place (subtracts n when a >= n).
        private static void AddNC(uint[] a, int ao)
        {
            ulong v = (ulong)a[ao] + NC0;
            a[ao] = (uint)(v & Mask32);
            v = (ulong)a[ao + 1] + NC1 + (v >> 32);
            a[ao + 1] = (uint)(v & Mask32);
            v = (ulong)a[ao + 2] + NC2 + (v >> 32);
            a[ao + 2] = (uint)(v & Mask32);
            v = (ulong)a[ao + 3] + NC3 + (v >> 32);
            a[ao + 3] = (uint)(v & Mask32);
            v = (ulong)a[ao + 4] + 1UL + (v >> 32);
            a[ao + 4] = (uint)(v & Mask32);
            ulong carry = v >> 32;
            for (int i = 5; i < 8 && carry != 0; i++)
            {
                v = (ulong)a[ao + i] + carry;
                a[ao + i] = (uint)(v & Mask32);
                carry = v >> 32;
            }
        }

        // 32 big-endian bytes at src[srcOffset..] -> 8 limbs at dst[dstOffset..].
        public static void FromBytes(byte[] src, int srcOffset, uint[] dst, int dstOffset)
        {
            for (int i = 0; i < 8; i++)
            {
                int b = srcOffset + 28 - 4 * i;
                dst[dstOffset + i] = ((uint)src[b] << 24) | ((uint)src[b + 1] << 16) | ((uint)src[b + 2] << 8) | src[b + 3];
            }
        }

        // 8 limbs at src[srcOffset..] -> 32 big-endian bytes at dst[dstOffset..].
        public static void ToBytes(uint[] src, int srcOffset, byte[] dst, int dstOffset)
        {
            for (int i = 0; i < 8; i++)
            {
                uint limb = src[srcOffset + i];
                int b = dstOffset + 28 - 4 * i;
                dst[b] = (byte)(limb >> 24);
                dst[b + 1] = (byte)((limb >> 16) & 0xFFu);
                dst[b + 2] = (byte)((limb >> 8) & 0xFFu);
                dst[b + 3] = (byte)(limb & 0xFFu);
            }
        }
    }
}
