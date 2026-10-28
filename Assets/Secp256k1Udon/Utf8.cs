using System;

namespace Secp256k1Udon
{
    // Manual UTF-8 encoder for C# (UTF-16) strings. Surrogate pairs become one 4-byte sequence;
    // unpaired surrogates become U+FFFD (EF BF BD), matching Java's and .NET's encoders.
    public static class Utf8
    {
        public static byte[] Encode(string s)
        {
            int n = s.Length;
            // Each UTF-16 unit takes at most 3 bytes (a pair takes 4 for 2 units).
            byte[] buffer = new byte[n * 3];
            int length = 0;

            for (int i = 0; i < n; i++)
            {
                int c = s[i];
                if (c < 0x80)
                {
                    buffer[length++] = (byte)c;
                }
                else if (c < 0x800)
                {
                    buffer[length++] = (byte)(0xC0 | (c >> 6));
                    buffer[length++] = (byte)(0x80 | (c & 0x3F));
                }
                else
                {
                    if (c >= 0xD800 && c <= 0xDFFF)
                    {
                        int lo = i + 1 < n ? s[i + 1] : 0;
                        if (c <= 0xDBFF && lo >= 0xDC00 && lo <= 0xDFFF)
                        {
                            int cp = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                            buffer[length++] = (byte)(0xF0 | (cp >> 18));
                            buffer[length++] = (byte)(0x80 | ((cp >> 12) & 0x3F));
                            buffer[length++] = (byte)(0x80 | ((cp >> 6) & 0x3F));
                            buffer[length++] = (byte)(0x80 | (cp & 0x3F));
                            i++;
                            continue;
                        }
                        c = 0xFFFD;
                    }
                    buffer[length++] = (byte)(0xE0 | (c >> 12));
                    buffer[length++] = (byte)(0x80 | ((c >> 6) & 0x3F));
                    buffer[length++] = (byte)(0x80 | (c & 0x3F));
                }
            }

            byte[] bytes = new byte[length];
            Array.Copy(buffer, bytes, length);
            return bytes;
        }
    }
}
