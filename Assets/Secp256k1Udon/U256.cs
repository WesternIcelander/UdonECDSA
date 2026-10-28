namespace Secp256k1Udon
{
    // 256-bit numbers as 8 x 32-bit limbs in a uint[] at an offset, least significant limb first.
    public static class U256
    {
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
