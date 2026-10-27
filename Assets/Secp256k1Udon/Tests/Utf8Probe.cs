using UdonSharp;
using UnityEngine;

namespace Secp256k1Udon.Tests
{
    // Phase 0 SDK capability check: is System.Text.Encoding.UTF8 exposed to Udon?
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class Utf8Probe : UdonSharpBehaviour
    {
        private void Start()
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes("a\u00e9\u20ac\U0001F600");
            Debug.Log("[Utf8Probe] " + bytes.Length + " bytes (expected 10)");
        }
    }
}
