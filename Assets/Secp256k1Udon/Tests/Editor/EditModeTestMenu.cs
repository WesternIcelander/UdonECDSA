using UnityEditor;
using UnityEditor.SceneManagement;
using UnityEditor.TestTools.TestRunner.Api;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace Secp256k1Udon.Tests.Editor
{
    // Runs this assembly's EditMode tests from a menu item (so the editor trigger can start them)
    // and logs one summary line: "[EditModeTests] done: N passed, M failed".
    public static class EditModeTestMenu
    {
        [MenuItem("Tools/Secp256k1Udon/Run EditMode Tests")]
        public static void Run()
        {
            // The test runner asks to save a modified scene with a modal dialog, which blocks unattended runs.
            // The generated test scene gets marked modified again after Build Test Scene saves it, so save it here.
            var scene = SceneManager.GetActiveScene();
            if (scene.isDirty && scene.path == TestSceneBuilder.ScenePath) EditorSceneManager.SaveScene(scene);

            var api = ScriptableObject.CreateInstance<TestRunnerApi>();
            api.RegisterCallbacks(new Callbacks());
            api.Execute(new ExecutionSettings(new Filter
            {
                testMode = TestMode.EditMode,
                assemblyNames = new[] { "Secp256k1Udon.Tests.Editor" },
            }));
        }

        private class Callbacks : ICallbacks
        {
            public void RunStarted(ITestAdaptor testsToRun) { }

            public void RunFinished(ITestResultAdaptor result)
            {
                Debug.Log("[EditModeTests] done: " + result.PassCount + " passed, " + result.FailCount + " failed");
            }

            public void TestStarted(ITestAdaptor test) { }

            public void TestFinished(ITestResultAdaptor result)
            {
                if (result.HasChildren) return;
                if (result.TestStatus == TestStatus.Failed)
                {
                    Debug.LogWarning("[EditModeTests] FAIL " + result.FullName + ": " + result.Message);
                }
                else
                {
                    Debug.Log("[EditModeTests] " + result.TestStatus.ToString().ToUpperInvariant() + " " + result.FullName);
                }
            }
        }
    }
}
