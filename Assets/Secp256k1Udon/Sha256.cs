using System;

namespace Secp256k1Udon
{
    // SHA-256 over byte[]. Static classes cannot hold fields in Udon, so the caller owns the working
    // buffer: allocate it once with NewScratch() and pass it to every Hash call (round constants,
    // message schedule and state live there, so hashing allocates nothing).
    public static class Sha256
    {
        // Scratch layout: K at [0..63], message schedule W at [64..127], state H at [128..135].
        public const int ScratchLength = 136;
        private const int W = 64;
        private const int H = 128;

        public static uint[] NewScratch()
        {
            uint[] k =
            {
                0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
                0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
                0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
                0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
                0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
                0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
                0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
                0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
            };
            uint[] scratch = new uint[ScratchLength];
            Array.Copy(k, scratch, 64);
            return scratch;
        }

        // Writes the 32-byte digest of data to output[outputOffset..].
        public static void Hash(byte[] data, uint[] scratch, byte[] output, int outputOffset)
        {
            Begin(scratch);
            ProcessBlocks(data, 0, BlockCount(data.Length), scratch);
            Finish(scratch, output, outputOffset);
        }

        // The hash can also be run in slices: Begin, ProcessBlocks over blocks 0 .. BlockCount(data.Length) - 1
        // in order and in as many calls as wanted, then Finish. The data must not change in between.

        // Number of 64-byte blocks hashed for a message of `length` bytes (message, 0x80, zeros, 64-bit length).
        public static int BlockCount(int length)
        {
            return (length + 9 + 63) >> 6;
        }

        public static void Begin(uint[] scratch)
        {
            uint[] s = scratch;
            s[H] = 0x6a09e667u;
            s[H + 1] = 0xbb67ae85u;
            s[H + 2] = 0x3c6ef372u;
            s[H + 3] = 0xa54ff53au;
            s[H + 4] = 0x510e527fu;
            s[H + 5] = 0x9b05688cu;
            s[H + 6] = 0x1f83d9abu;
            s[H + 7] = 0x5be0cd19u;
        }

        // Hashes blocks fromBlock .. fromBlock + count - 1 of data (padding included) into the state.
        public static void ProcessBlocks(byte[] data, int fromBlock, int count, uint[] scratch)
        {
            uint[] s = scratch;
            int length = data.Length;
            int blocks = BlockCount(length);
            int fullBlocks = length >> 6;
            ulong bitLength = (ulong)length << 3;

            for (int block = fromBlock; block < fromBlock + count; block++)
            {
                int start = block << 6;
                if (block < fullBlocks)
                {
                    for (int j = 0; j < 16; j++)
                    {
                        int i = start + 4 * j;
                        s[W + j] = ((uint)data[i] << 24) | ((uint)data[i + 1] << 16) | ((uint)data[i + 2] << 8) | data[i + 3];
                    }
                }
                else
                {
                    // Padding block(s): message tail, then 0x80, then zeros, then the length in the last 8 bytes.
                    for (int j = 0; j < 16; j++)
                    {
                        uint word = 0;
                        for (int t = 0; t < 4; t++)
                        {
                            int i = start + 4 * j + t;
                            uint value = i < length ? data[i] : (i == length ? 0x80u : 0u);
                            word = (word << 8) | value;
                        }
                        s[W + j] = word;
                    }
                    if (block == blocks - 1)
                    {
                        s[W + 14] = (uint)(bitLength >> 32);
                        s[W + 15] = (uint)(bitLength & 0xFFFFFFFFUL);
                    }
                }

                for (int j = 16; j < 64; j++)
                {
                    uint w15 = s[W + j - 15];
                    uint w2 = s[W + j - 2];
                    uint s0 = ((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3);
                    uint s1 = ((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10);
                    s[W + j] = s[W + j - 16] + s0 + s[W + j - 7] + s1;
                }

                uint a = s[H];
                uint b = s[H + 1];
                uint c = s[H + 2];
                uint d = s[H + 3];
                uint e = s[H + 4];
                uint f = s[H + 5];
                uint g = s[H + 6];
                uint h = s[H + 7];

                for (int j = 0; j < 64; j++)
                {
                    uint sum1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
                    uint ch = g ^ (e & (f ^ g));
                    uint t1 = h + sum1 + ch + s[j] + s[W + j];
                    uint sum0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
                    uint maj = (a & b) | (c & (a | b));
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + sum0 + maj;
                }

                s[H] += a;
                s[H + 1] += b;
                s[H + 2] += c;
                s[H + 3] += d;
                s[H + 4] += e;
                s[H + 5] += f;
                s[H + 6] += g;
                s[H + 7] += h;
            }
        }

        // Writes the 32-byte digest to output[outputOffset..] once every block has been processed.
        public static void Finish(uint[] scratch, byte[] output, int outputOffset)
        {
            uint[] s = scratch;
            for (int i = 0; i < 8; i++)
            {
                uint word = s[H + i];
                int o = outputOffset + 4 * i;
                output[o] = (byte)(word >> 24);
                output[o + 1] = (byte)((word >> 16) & 0xFFu);
                output[o + 2] = (byte)((word >> 8) & 0xFFu);
                output[o + 3] = (byte)(word & 0xFFu);
            }
        }
    }
}
