using System.Text.RegularExpressions;
using NUnit.Framework;
using UnityEditor;
using UnityEngine;
using UnityEngine.TestTools;

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
                var vectors = AssetDatabase.LoadAssetAtPath<TextAsset>(VectorsPath);
                var verifier = go.AddComponent<SignatureVerifier>();
                verifier.publicKeyHex = TestSceneBuilder.TestPublicKey(vectors.text);
                var invalidKeyVerifier = go.AddComponent<SignatureVerifier>();
                invalidKeyVerifier.publicKeyHex = TestSceneBuilder.InvalidPublicKey;
                // The invalid-key verifier logs this error on first use, which would otherwise fail the test.
                LogAssert.Expect(LogType.Error, new Regex(@"\[SignatureVerifier\] invalid public key"));

                var tests = go.AddComponent<VectorTests>();
                tests.vectors = vectors;
                tests.verifier = verifier;
                tests.invalidKeyVerifier = invalidKeyVerifier;
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
