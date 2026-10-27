using System;
using System.IO;
using System.Linq;
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
        private const string ScenePath = "Assets/Secp256k1Udon/Tests/TestScene.unity";
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
                    vectorTests.vectors = AssetDatabase.LoadAssetAtPath<TextAsset>(VectorsPath);
                    UdonSharpEditorUtility.CopyProxyToUdon(vectorTests);
                }
            }

            EditorSceneManager.SaveScene(scene, ScenePath);
            Debug.Log("[TestSceneBuilder] built " + ScenePath);
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
