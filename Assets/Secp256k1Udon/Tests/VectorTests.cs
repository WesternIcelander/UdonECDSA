using UdonSharp;
using UnityEngine;
using VRC.SDK3.Data;

namespace Secp256k1Udon.Tests
{
    // Runs the vectors in Vectors/vectors.json against the library. The same code runs in two places:
    // inside the Udon VM in Play Mode (Start), which is authoritative, and as plain C# from the EditMode
    // test (VectorTestsEditMode calls RunAll), for fast iteration. Logs PASS/FAIL per case and a summary line.
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class VectorTests : UdonSharpBehaviour
    {
        public TextAsset vectors;

        [HideInInspector] public int passed;
        [HideInInspector] public int failed;
        [HideInInspector] public bool done;

        private DataDictionary root;

        private void Start()
        {
            RunAll();
        }

        public void RunAll()
        {
            passed = 0;
            failed = 0;
            done = false;

            if (LoadVectors())
            {
                CheckSections();
            }

            done = true;
            Debug.Log("[VectorTests] done: " + passed + " passed, " + failed + " failed");
        }

        private bool LoadVectors()
        {
            if (vectors == null)
            {
                Report("load vectors", false, "no vectors TextAsset assigned");
                return false;
            }
            DataToken token;
            if (!VRCJson.TryDeserializeFromJson(vectors.text, out token) || token.TokenType != TokenType.DataDictionary)
            {
                Report("load vectors", false, "vectors.json did not parse to an object");
                return false;
            }
            root = token.DataDictionary;
            Report("load vectors", true, "");
            return true;
        }

        // Harness self-check: every section the later phases test is present and non-empty.
        private void CheckSections()
        {
            DataToken key;
            bool keyOk = root.TryGetValue("testPublicKey", TokenType.String, out key) && key.String.Length == 130;
            Report("section testPublicKey", keyOk, "missing or not 130 hex chars");

            CheckList("hashVectors");
            CheckList("sha256");
            CheckList("field");
            CheckList("scalar");
            CheckList("points");
            CheckList("doubleMul");
            CheckList("signatures");
            CheckList("signatureFlips");
            CheckList("publicKeys");
        }

        private void CheckList(string name)
        {
            DataToken list;
            bool ok = root.TryGetValue(name, TokenType.DataList, out list) && list.DataList.Count > 0;
            Report("section " + name + (ok ? " (" + list.DataList.Count + " cases)" : ""), ok, "missing or empty");
        }

        private void Report(string name, bool ok, string failDetail)
        {
            if (ok)
            {
                passed++;
                Debug.Log("[VectorTests] PASS " + name);
            }
            else
            {
                failed++;
                Debug.LogWarning("[VectorTests] FAIL " + name + ": " + failDetail);
            }
        }
    }
}
