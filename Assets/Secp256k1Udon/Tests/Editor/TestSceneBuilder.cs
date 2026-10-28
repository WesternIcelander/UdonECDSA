using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using UdonSharp;
using UdonSharp.Compiler;
using UdonSharpEditor;
using UnityEditor;
using UnityEditor.SceneManagement;
using UnityEngine;

namespace Secp256k1Udon.Tests.Editor
{
    // Builds the Play Mode test scene: one GameObject per test behaviour in the Secp256k1Udon.Tests assembly.
    public static class TestSceneBuilder
    {
        private const string LibraryFolder = "Assets/Secp256k1Udon";
        public const string ScenePath = "Assets/Secp256k1Udon/Tests/TestScene.unity";
        private const string VectorsPath = "Assets/Secp256k1Udon/Tests/Vectors/vectors.json";
        private const string WorldPrefabPath = "Packages/com.vrchat.worlds/Samples/UdonExampleScene/Prefabs/VRCWorld.prefab";

        [MenuItem("Tools/Secp256k1Udon/Build Test Scene")]
        public static void Build()
        {
            EnsureProgramAssets();
            UdonSharpCompilerV1.CompileSync();

            var scene = EditorSceneManager.NewScene(NewSceneSetup.DefaultGameObjects, NewSceneMode.Single);
            var worldPrefab = AssetDatabase.LoadAssetAtPath<GameObject>(WorldPrefabPath);
            PrefabUtility.InstantiatePrefab(worldPrefab, scene);

            var vectorsAsset = AssetDatabase.LoadAssetAtPath<TextAsset>(VectorsPath);
            var verifier = AddVerifier("SignatureVerifier", TestPublicKey(vectorsAsset.text));
            var invalidKeyVerifier = AddVerifier("SignatureVerifier (invalid key)", InvalidPublicKey);

            var testAssembly = typeof(Phase0Probe).Assembly;
            var testTypes = testAssembly.GetTypes()
                .Where(t => typeof(UdonSharpBehaviour).IsAssignableFrom(t) && !t.IsAbstract)
                .OrderBy(t => t.Name);
            foreach (Type type in testTypes)
            {
                var go = new GameObject(type.Name);
                UdonSharpBehaviour behaviour = UdonSharpUndo.AddComponent(go, type);
                if (behaviour is VectorTests vectorTests)
                {
                    vectorTests.vectors = vectorsAsset;
                    vectorTests.verifier = verifier;
                    vectorTests.invalidKeyVerifier = invalidKeyVerifier;
                    UdonSharpEditorUtility.CopyProxyToUdon(vectorTests);
                }
            }

            EditorSceneManager.SaveScene(scene, ScenePath);
            Debug.Log("[TestSceneBuilder] built " + ScenePath);
        }

        // The point (0, 0), which is not on the curve.
        public const string InvalidPublicKey =
            "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        public static string TestPublicKey(string vectorsJson)
        {
            var match = Regex.Match(vectorsJson, "\"testPublicKey\":\\s*\"([0-9a-fA-F]+)\"");
            if (!match.Success) throw new InvalidOperationException("vectors.json has no testPublicKey");
            return match.Groups[1].Value;
        }

        private static SignatureVerifier AddVerifier(string name, string publicKeyHex)
        {
            var go = new GameObject(name);
            var verifier = (SignatureVerifier)UdonSharpUndo.AddComponent(go, typeof(SignatureVerifier));
            verifier.publicKeyHex = publicKeyHex;
            UdonSharpEditorUtility.CopyProxyToUdon(verifier);
            return verifier;
        }

        // UdonSharp only creates a script's program asset from its editor UI, so create any that are missing.
        private static void EnsureProgramAssets()
        {
            foreach (string guid in AssetDatabase.FindAssets("t:MonoScript", new[] { LibraryFolder }))
            {
                string scriptPath = AssetDatabase.GUIDToAssetPath(guid);
                var script = AssetDatabase.LoadAssetAtPath<MonoScript>(scriptPath);
                Type type = script.GetClass();
                if (type == null || !typeof(UdonSharpBehaviour).IsAssignableFrom(type)) continue;

                string assetPath = Path.ChangeExtension(scriptPath, ".asset");
                if (AssetDatabase.LoadAssetAtPath<UdonSharpProgramAsset>(assetPath) != null) continue;

                var programAsset = ScriptableObject.CreateInstance<UdonSharpProgramAsset>();
                programAsset.sourceCsScript = script;
                AssetDatabase.CreateAsset(programAsset, assetPath);
                Debug.Log("[TestSceneBuilder] created " + assetPath);
            }
            AssetDatabase.SaveAssets();
        }
    }
}
