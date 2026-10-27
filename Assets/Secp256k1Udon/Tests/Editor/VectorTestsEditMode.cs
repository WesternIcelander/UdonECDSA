using NUnit.Framework;
using UnityEditor;
using UnityEngine;

namespace Secp256k1Udon.Tests.Editor
{
    // EditMode path: runs VectorTests as plain C#, outside the Udon VM. Necessary but not sufficient;
    // the Play Mode (Udon) run of the same behaviour is authoritative.
    public class VectorTestsEditMode
    {
        private const string VectorsPath = "Assets/Secp256k1Udon/Tests/Vectors/vectors.json";

        [Test]
        public void AllVectorsPass()
        {
            var go = new GameObject("VectorTestsEditMode") { hideFlags = HideFlags.HideAndDontSave };
            try
            {
                var tests = go.AddComponent<VectorTests>();
                tests.vectors = AssetDatabase.LoadAssetAtPath<TextAsset>(VectorsPath);
                tests.RunAll();

                Assert.IsTrue(tests.done, "runner did not finish");
                Assert.Greater(tests.passed, 0, "no cases ran");
                Assert.AreEqual(0, tests.failed, tests.failed + " cases failed (see the [VectorTests] FAIL lines)");
            }
            finally
            {
                Object.DestroyImmediate(go);
            }
        }
    }
}
