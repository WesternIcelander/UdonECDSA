using UdonSharp;
using UnityEngine;

namespace Secp256k1Udon.Tests
{
    // Phase 9 measurement: how long the verification building blocks take in Udon, to size the frame slices.
    // One measurement per frame, so no event comes near Udon's 10 s limit. Logs one line per measurement and
    // "[TimingProbe] done" at the end.
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class TimingProbe : UdonSharpBehaviour
    {
        // The PLAN.md Phase 1 example: an ECSandbox signature over a precomputed hash.
        private const string PublicKey = "0482c0b07b91d483e3f8f3c1c5336512da70e559db264554a4f3dba8b6da2875a7351728ff3b584a105cb4d992fba5584f64919374f136c2137455655cc4095e82";
        private const string Hash = "f0ec4ead0758e7fc50cb73cfa1eb97626637a934ec8f8c1bb7c20a2cc5ac1ddc";
        private const string Signature = "17e4684dd69e178639d8fc8c7412c3e764ace8f8d407cb2572ca03caf75650f1c343df2ce4839762e0be9c9bfd1cf0b0aabebe8efaa364df305781877d83dd2601";

        private uint[] s;
        private ulong[] t;
        private uint[] key;
        private byte[] hash;
        private uint[] sha;
        private byte[] message;
        private uint[] buf;
        private int step;

        private void Start()
        {
            s = Secp256k1.NewScratch();
            t = new ulong[U256.ProductScratchLength];
            key = new uint[Secp256k1.AffineLength];
            sha = Sha256.NewScratch();
            hash = Hex.Decode(Hash);
            message = new byte[300];
            for (int i = 0; i < message.Length; i++) message[i] = (byte)(i & 0xFF);
            buf = new uint[Secp256k1.PointLength * 2];
            Secp256k1.LoadPublicKey(PublicKey, key, 0, s, t);
            Secp256k1.FromAffine(s, Secp256k1.GOffset, buf, 0);
            Secp256k1.Double(buf, 0, buf, 0, s, t);
            Secp256k1.FromAffine(key, 0, buf, Secp256k1.PointLength);
            Secp256k1.Double(buf, Secp256k1.PointLength, buf, Secp256k1.PointLength, s, t);
            step = 0;
            SendCustomEventDelayedFrames(nameof(RunNextStep), 1);
        }

        public void RunNextStep()
        {
            System.Diagnostics.Stopwatch w = System.Diagnostics.Stopwatch.StartNew();
            string name;
            int reps = 1;
            int current = step++;
            if (current == 0)
            {
                name = "FieldMul";
                reps = 100;
                for (int i = 0; i < reps; i++) U256.FieldMul(buf, 0, buf, 8, buf, 16, t);
            }
            else if (current == 1)
            {
                name = "FieldSqr";
                reps = 100;
                for (int i = 0; i < reps; i++) U256.FieldSqr(buf, 0, buf, 16, t);
            }
            else if (current == 2)
            {
                name = "FieldAdd";
                reps = 100;
                for (int i = 0; i < reps; i++) U256.FieldAdd(buf, 0, buf, 8, buf, 16);
            }
            else if (current == 3)
            {
                name = "ScalarMul";
                reps = 100;
                for (int i = 0; i < reps; i++) U256.ScalarMul(buf, 0, buf, 8, buf, 16, t);
            }
            else if (current == 4)
            {
                name = "Double";
                reps = 20;
                for (int i = 0; i < reps; i++) Secp256k1.Double(buf, 0, buf, 0, s, t);
            }
            else if (current == 5)
            {
                name = "AddAffine";
                reps = 20;
                for (int i = 0; i < reps; i++) Secp256k1.AddAffine(buf, 0, key, 0, buf, 0, s, t);
            }
            else if (current == 6)
            {
                name = "Add (Jacobian)";
                reps = 20;
                for (int i = 0; i < reps; i++) Secp256k1.Add(buf, 0, buf, Secp256k1.PointLength, buf, 0, s, t);
            }
            else if (current == 7)
            {
                name = "SHA-256 of 300 bytes";
                reps = 10;
                for (int i = 0; i < reps; i++) Sha256.Hash(message, sha, hash, 0);
                hash = Hex.Decode(Hash);
            }
            else if (current == 8)
            {
                name = "Utf8.Encode of 300 chars";
                string text = new string('a', 300);
                reps = 10;
                for (int i = 0; i < reps; i++) Utf8.Encode(text);
            }
            else if (current == 9)
            {
                name = "VerifyParse";
                reps = 10;
                for (int i = 0; i < reps; i++) Secp256k1.VerifyParse(Signature, s);
            }
            else if (current == 10)
            {
                name = "ScalarInv";
                U256.ScalarInv(s, Secp256k1.SOffset, s, Secp256k1.U2Offset, s, Secp256k1.U2Offset + 8, t);
            }
            else if (current == 11)
            {
                name = "VerifySetup";
                Secp256k1.VerifyParse(Signature, s);
                Secp256k1.VerifySetup(hash, 0, key, 0, s, t);
            }
            else if (current == 12)
            {
                name = "DoubleMulBits, 16 bits";
                Secp256k1.DoubleMulBits(s, Secp256k1.U1Offset, s, Secp256k1.U2Offset, 255, 16, s, t);
            }
            else if (current == 13)
            {
                name = "full VerifyHash";
                bool ok = Secp256k1.VerifyHash(hash, 0, Signature, key, 0, s, t);
                if (!ok) Debug.LogWarning("[TimingProbe] the example signature did not verify");
            }
            else
            {
                Debug.Log("[TimingProbe] done");
                return;
            }
            w.Stop();
            double ms = w.Elapsed.TotalMilliseconds;
            Debug.Log("[TimingProbe] " + name + ": " + (ms / reps).ToString("F4") + " ms each (" + reps + " runs, " + ms.ToString("F2") + " ms)");
            SendCustomEventDelayedFrames(nameof(RunNextStep), 1);
        }
    }
}
