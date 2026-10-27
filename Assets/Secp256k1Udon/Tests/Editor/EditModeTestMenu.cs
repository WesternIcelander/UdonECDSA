using UnityEditor;
using UnityEditor.TestTools.TestRunner.Api;
using UnityEngine;

namespace Secp256k1Udon.Tests.Editor
{
    // Runs this assembly's EditMode tests from a menu item (so the editor trigger can start them)
    // and logs one summary line: "[EditModeTests] done: N passed, M failed".
    public static class EditModeTestMenu
    {
        [MenuItem("Tools/Secp256k1Udon/Run EditMode Tests")]
        public static void Run()
        {
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
