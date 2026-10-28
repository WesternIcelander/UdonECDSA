namespace Secp256k1Udon
{
    // Hex string <-> byte[]. Decoding accepts either case; encoding is always lowercase.
    public static class Hex
    {
        private const string Digits = "0123456789abcdef";

        // Returns null on odd length or any non-hex character (no exceptions: Udon cannot catch them).
        public static byte[] Decode(string hex)
        {
            if (hex == null) return null;
            int length = hex.Length;
            if ((length & 1) != 0) return null;

            byte[] bytes = new byte[length >> 1];
            for (int i = 0; i < bytes.Length; i++)
            {
                int hi = Nibble(hex[2 * i]);
                int lo = Nibble(hex[2 * i + 1]);
                if (hi < 0 || lo < 0) return null;
                bytes[i] = (byte)((hi << 4) | lo);
            }
            return bytes;
        }

        // 64 hex chars (either case) at hex[offset..] as a big-endian 256-bit number -> 8 limbs at dst[dstOffset..]
        // (U256 order). Returns false, possibly with dst partly written, on any non-hex character. The caller
        // checks that the 64 chars exist. Allocates nothing.
        public static bool DecodeLimbs(string hex, int offset, uint[] dst, int dstOffset)
        {
            for (int i = 0; i < 8; i++)
            {
                uint limb = 0u;
                int c = offset + 56 - 8 * i;
                for (int j = 0; j < 8; j++)
                {
                    int nibble = Nibble(hex[c + j]);
                    if (nibble < 0) return false;
                    limb = (limb << 4) | (uint)nibble;
                }
                dst[dstOffset + i] = limb;
            }
            return true;
        }

        // True if hex[offset..offset+length-1] are all hex characters (either case). The caller checks the range exists.
        public static bool IsHex(string hex, int offset, int length)
        {
            for (int i = offset; i < offset + length; i++)
            {
                if (Nibble(hex[i]) < 0) return false;
            }
            return true;
        }

        public static string Encode(byte[] bytes)
        {
            char[] chars = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int b = bytes[i];
                chars[2 * i] = Digits[b >> 4];
                chars[2 * i + 1] = Digits[b & 0xF];
            }
            return new string(chars);
        }

        private static int Nibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    }
}
