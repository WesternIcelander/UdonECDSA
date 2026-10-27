using UdonSharp;
using UnityEngine;

namespace Secp256k1Udon.Tests
{
    // Phase 0 SDK capability checks: run in Play Mode, logs one line per check.
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class Phase0Probe : UdonSharpBehaviour
    {
        private void Start()
        {
            Debug.Log("[Phase0Probe] done");
        }
    }
}
