using UdonSharp;
using UnityEngine;

namespace Secp256k1Udon.Tests
{
    // Phase 0 SDK capability check: does uint/ulong arithmetic wrap in Udon the same way as unchecked C#?
    // Inputs are fields set at runtime so neither compiler can fold the expressions into constants.
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class Phase0Probe : UdonSharpBehaviour
    {
        private uint uZero;
        private uint uOne;
        private uint uMax;
        private ulong ulOne;
        private ulong ulMax;
        private ulong ulPattern;
        private int iMax;

        private int passed;
        private int failed;

        private void Start()
        {
            uZero = (uint)Random.Range(0, 1);
            uOne = uZero + 1u;
            uMax = uZero + 0xFFFFFFFFu;
            ulOne = uOne;
            ulMax = ulOne * 0xFFFFFFFFFFFFFFFFUL;
            ulPattern = ulOne * 0x123456789ABCDEF0UL;
            iMax = (int)uZero + int.MaxValue;

            CheckU("uint max + 1", uMax + uOne, 0u);
            CheckU("uint 0 - 1", uZero - uOne, 0xFFFFFFFFu);
            CheckU("uint max * max", uMax * uMax, 1u);
            CheckU("uint << 31 << 1", (uOne << 31) << 1, 0u);
            CheckUL("ulong max + 1", ulMax + ulOne, 0UL);
            CheckUL("ulong 0 - 1", (ulOne - ulOne) - ulOne, 0xFFFFFFFFFFFFFFFFUL);
            CheckUL("(ulong)uint max * uint max", (ulong)uMax * uMax, 0xFFFFFFFE00000001UL);
            CheckUL("ulong max * max", ulMax * ulMax, 1UL);
            CheckUL("(ulong)uint max * max + max + max", (ulong)uMax * uMax + uMax + uMax, 0xFFFFFFFFFFFFFFFFUL);
            // Udon compiles narrowing casts to checked System.Convert calls: (uint)ulPattern throws
            // "Value was either too large or too small for a UInt32" and halts the behaviour. Mask first.
            CheckU("(uint)(ulong & 0xFFFFFFFF)", (uint)(ulPattern & 0xFFFFFFFFUL), 0x9ABCDEF0u);
            CheckU("(uint)(ulong >> 32)", (uint)(ulPattern >> 32), 0x12345678u);
            CheckU("(uint)(max * max & 0xFFFFFFFF)", (uint)(((ulong)uMax * uMax) & 0xFFFFFFFFUL), 1u);
            CheckU("(uint)(byte)(uint & 0xFF)", (byte)(uMax & 0xFFu), 0xFFu);
            CheckUL("ulong << 32 carries into high half", ((ulong)uMax << 32) + uMax, 0xFFFFFFFFFFFFFFFFUL);
            CheckI("int max + 1", iMax + 1, int.MinValue);

            Debug.Log("[Phase0Probe] done: " + passed + " passed, " + failed + " failed");
        }

        private void CheckU(string name, uint actual, uint expected)
        {
            Report(name, actual == expected, actual.ToString("X8"), expected.ToString("X8"));
        }

        private void CheckUL(string name, ulong actual, ulong expected)
        {
            Report(name, actual == expected, actual.ToString("X16"), expected.ToString("X16"));
        }

        private void CheckI(string name, int actual, int expected)
        {
            Report(name, actual == expected, actual.ToString(), expected.ToString());
        }

        private void Report(string name, bool ok, string actual, string expected)
        {
            if (ok)
            {
                passed++;
                Debug.Log("[Phase0Probe] PASS " + name);
            }
            else
            {
                failed++;
                Debug.LogWarning("[Phase0Probe] FAIL " + name + ": got " + actual + ", expected " + expected);
            }
        }
    }
}
