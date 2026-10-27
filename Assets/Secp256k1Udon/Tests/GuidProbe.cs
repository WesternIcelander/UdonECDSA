using UdonSharp;
using UnityEngine;

namespace Secp256k1Udon.Tests
{
    // Phase 0 SDK capability check: is System.Guid.NewGuid() exposed to Udon?
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class GuidProbe : UdonSharpBehaviour
    {
        private void Start()
        {
            string guid = System.Guid.NewGuid().ToString();
            Debug.Log("[GuidProbe] " + guid + " (lowercase: " + (guid == guid.ToLowerInvariant()) + ")");
        }
    }
}
