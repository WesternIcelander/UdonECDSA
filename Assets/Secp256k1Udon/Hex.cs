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
