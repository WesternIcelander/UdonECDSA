using UdonSharp;
using UnityEngine;

namespace Secp256k1Udon.Tests
{
    // Phase 0 SDK capability check: is System.Diagnostics.Stopwatch exposed to Udon?
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class StopwatchProbe : UdonSharpBehaviour
    {
        private void Start()
        {
            System.Diagnostics.Stopwatch stopwatch = System.Diagnostics.Stopwatch.StartNew();
            int sum = 0;
            for (int i = 0; i < 10000; i++) sum += i;
            stopwatch.Stop();
            Debug.Log("[StopwatchProbe] 10000 iterations: " + stopwatch.Elapsed.TotalMilliseconds + " ms, " + stopwatch.ElapsedTicks + " ticks, frequency " + System.Diagnostics.Stopwatch.Frequency + " (sum " + sum + ")");
        }
    }
}
