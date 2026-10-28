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
        // Verifiers holding the vectors' test public key and an invalid key (set by the test scene builder and the
        // EditMode test).
        public SignatureVerifier verifier;
        public SignatureVerifier invalidKeyVerifier;

        [HideInInspector] public int passed;
        [HideInInspector] public int failed;
        [HideInInspector] public bool done;

        private DataDictionary root;

        private int step;
        // EditMode (RunAll): delayed events do not run, so the sliced verifiers are driven with ProcessAllNow.
        private bool runAllMode;

        // Udon halts a behaviour after 10 seconds in one event, so in Play Mode the checks run as steps, one per
        // frame (each signature case is a step of its own).
        private void Start()
        {
            runAllMode = false;
            BeginRun();
            RunNextStep();
        }

        public void RunNextStep()
        {
            if (RunStep()) SendCustomEventDelayedFrames(nameof(RunNextStep), 1);
        }

        // EditMode: every step in one call.
        public void RunAll()
        {
            runAllMode = true;
            BeginRun();
            while (RunStep()) { }
        }

        private void BeginRun()
        {
            passed = 0;
            failed = 0;
            done = false;
            step = 0;
        }

        // Runs the next step; returns false once the run is done.
        private bool RunStep()
        {
            int current = step++;
            if (current == 0)
            {
                if (!LoadVectors()) return Finish();
                CheckSections();
                CheckHex();
                CheckUtf8();
                CheckLimbs();
                CheckSha256();
                return true;
            }
            if (current == 1) { CheckField(); return true; }
            if (current == 2) { CheckScalar(); return true; }
            if (current == 3) { CheckCurve(); return true; }
            if (current == 4) { BeginEcdsa(); return true; }

            int index = current - 5;
            int signatures = GetList("signatures").Count;
            if (index < signatures) { CheckSignatureEntry("signatures", index); return true; }
            index -= signatures;
            int flips = GetList("signatureFlips").Count;
            if (index < flips) { CheckSignatureEntry("signatureFlips", index); return true; }
            index -= flips;
            if (index == 0) { EndEcdsa(); return true; }
            // Phase 9: the sliced verifier, two rounds of requests; each waiting step repeats until its round is done.
            if (index == 1) { CheckSlicedPrimitives(); BeginSliced(0); return true; }
            if (index == 2)
            {
                if (SlicedPending()) step--;
                else { EndSlicedRound(); BeginSliced(1); }
                return true;
            }
            if (index == 3)
            {
                if (SlicedPending()) step--;
                else { EndSlicedRound(); EndSliced(); }
                return true;
            }
            return Finish();
        }

        private bool Finish()
        {
            done = true;
            Debug.Log("[VectorTests] done: " + passed + " passed, " + failed + " failed");
            return false;
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

        // Phase 3: Hex decode/encode, including rejection of malformed input.
        private void CheckHex()
        {
            CheckHexRoundTrip("hex empty", "", "");
            CheckHexRoundTrip("hex lowercase", "00ff10abcdef9a", "00ff10abcdef9a");
            CheckHexRoundTrip("hex uppercase", "00FF10ABCDEF9A", "00ff10abcdef9a");
            CheckHexRoundTrip("hex mixed case", "aBcDeF", "abcdef");

            byte[] bytes = Hex.Decode("00017f80feff");
            bool valuesOk = bytes != null && bytes.Length == 6 && bytes[0] == 0 && bytes[1] == 1
                && bytes[2] == 0x7f && bytes[3] == 0x80 && bytes[4] == 0xfe && bytes[5] == 0xff;
            Report("hex decode byte values", valuesOk, "wrong bytes");

            CheckHexRejected("hex reject odd length", "abc");
            CheckHexRejected("hex reject single char", "a");
            CheckHexRejected("hex reject 'g'", "0g");
            CheckHexRejected("hex reject 'G'", "G0");
            CheckHexRejected("hex reject ':' (after '9')", "0:");
            CheckHexRejected("hex reject '/' (before '0')", "/0");
            CheckHexRejected("hex reject '@' (before 'A')", "@0");
            CheckHexRejected("hex reject '`' (before 'a')", "`0");
            CheckHexRejected("hex reject space", "0 ");
            CheckHexRejected("hex reject 0x prefix", "0x12");
            CheckHexRejected("hex reject non-ASCII", "0á");
            CheckHexRejected("hex reject null", null);

            DataList keys = GetList("publicKeys");
            string lower = FindString(keys, "valid test key", "publicKey");
            string upper = FindString(keys, "uppercase hex", "publicKey");
            byte[] upperBytes = Hex.Decode(upper);
            Report("hex uppercase public key decodes to the lowercase key",
                upperBytes != null && lower != null && Hex.Encode(upperBytes) == lower, "mismatch");

            DataList sha = GetList("sha256");
            int roundTrips = 0;
            bool allOk = true;
            for (int i = 0; i < sha.Count; i++)
            {
                DataDictionary entry = sha[i].DataDictionary;
                string utf8 = entry["utf8"].String;
                string hash = entry["hash"].String;
                byte[] utf8Bytes = Hex.Decode(utf8);
                byte[] hashBytes = Hex.Decode(hash);
                allOk &= utf8Bytes != null && utf8Bytes.Length * 2 == utf8.Length && Hex.Encode(utf8Bytes) == utf8;
                allOk &= hashBytes != null && hashBytes.Length == 32 && Hex.Encode(hashBytes) == hash;
                roundTrips += 2;
            }
            Report("hex round trip of sha256 vector strings (" + roundTrips + " strings)", allOk, "a round trip differed");
        }

        private void CheckHexRoundTrip(string name, string input, string expected)
        {
            byte[] bytes = Hex.Decode(input);
            if (bytes == null)
            {
                Report(name, false, "decode returned null");
                return;
            }
            string encoded = Hex.Encode(bytes);
            Report(name, bytes.Length * 2 == input.Length && encoded == expected, "got " + encoded);
        }

        private void CheckHexRejected(string name, string input)
        {
            Report(name, Hex.Decode(input) == null, "decode did not return null");
        }

        // Phase 3: UTF-8 encoding of every vector that stores its expected utf8 bytes.
        private void CheckUtf8()
        {
            CheckUtf8List("sha256");
            CheckUtf8List("signatures");
            CheckUtf8List("signatureFlips");
        }

        private void CheckUtf8List(string listName)
        {
            DataList list = GetList(listName);
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                DataToken utf8;
                if (!entry.TryGetValue("utf8", TokenType.String, out utf8)) continue;
                string data = GetData(entry);
                if (data == null)
                {
                    Report("utf8 " + listName + ": " + entry["name"].String, false, "missing or malformed utf16 field");
                    continue;
                }
                string got = Hex.Encode(Utf8.Encode(data));
                Report("utf8 " + listName + ": " + entry["name"].String, got == utf8.String,
                    "expected " + utf8.String + ", got " + got);
            }
        }

        // An entry's `data` string, rebuilt from its `utf16` code units: VRCJson mis-parses surrogate escapes
        // such as \ud83d, so the parsed `data` field cannot be trusted for those strings.
        private string GetData(DataDictionary entry)
        {
            DataToken utf16;
            if (!entry.TryGetValue("utf16", TokenType.String, out utf16)) return null;
            byte[] units = Hex.Decode(utf16.String);
            if (units == null || (units.Length & 1) != 0) return null;
            char[] chars = new char[units.Length / 2];
            for (int i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)((units[2 * i] << 8) | units[2 * i + 1]);
            }
            return new string(chars);
        }

        // Phase 3: 32-byte big-endian <-> 8-limb conversions.
        private void CheckLimbs()
        {
            byte[] bytes = new byte[32];
            for (int i = 0; i < 32; i++) bytes[i] = (byte)i;
            uint[] limbs = new uint[8];
            U256.FromBytes(bytes, 0, limbs, 0);
            Report("limbs from bytes: limb order and byte order",
                limbs[7] == 0x00010203u && limbs[6] == 0x04050607u && limbs[1] == 0x18191a1bu && limbs[0] == 0x1c1d1e1fu,
                "limbs[7]=" + limbs[7].ToString("x8") + " limbs[0]=" + limbs[0].ToString("x8"));

            byte[] one = Hex.Decode("0000000000000000000000000000000000000000000000000000000000000001");
            U256.FromBytes(one, 0, limbs, 0);
            bool oneOk = limbs[0] == 1u;
            for (int i = 1; i < 8; i++) oneOk &= limbs[i] == 0u;
            Report("limbs from bytes: 1", oneOk, "wrong limbs");

            byte[] max = Hex.Decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            U256.FromBytes(max, 0, limbs, 0);
            bool maxOk = true;
            for (int i = 0; i < 8; i++) maxOk &= limbs[i] == 0xFFFFFFFFu;
            byte[] maxBack = new byte[32];
            U256.ToBytes(limbs, 0, maxBack, 0);
            Report("limbs 2^256 - 1 round trip", maxOk && Hex.Encode(maxBack) == Hex.Encode(max), "wrong limbs or bytes");

            // Offsets on both sides: bytes at 5 in a 40-byte array, limbs at 3 in a 12-limb array, back to 7.
            byte[] src = new byte[40];
            for (int i = 0; i < 32; i++) src[5 + i] = (byte)(0xA0 ^ (i * 7 & 0xFF));
            uint[] wide = new uint[12];
            U256.FromBytes(src, 5, wide, 3);
            byte[] dst = new byte[40];
            U256.ToBytes(wide, 3, dst, 7);
            bool offsetOk = wide[0] == 0u && wide[1] == 0u && wide[2] == 0u && wide[11] == 0u;
            for (int i = 0; i < 32; i++) offsetOk &= dst[7 + i] == src[5 + i];
            for (int i = 0; i < 7; i++) offsetOk &= dst[i] == 0;
            offsetOk &= dst[39] == 0;
            Report("limbs round trip with offsets", offsetOk, "bytes or untouched slots differ");

            DataList field = GetList("field");
            byte[] back = new byte[32];
            int count = 0;
            bool allOk = true;
            for (int i = 0; i < field.Count; i++)
            {
                DataDictionary entry = field[i].DataDictionary;
                DataToken a;
                if (!entry.TryGetValue("a", TokenType.String, out a) || a.String.Length != 64) continue;
                byte[] value = Hex.Decode(a.String);
                if (value == null)
                {
                    allOk = false;
                    continue;
                }
                U256.FromBytes(value, 0, limbs, 0);
                U256.ToBytes(limbs, 0, back, 0);
                allOk &= Hex.Encode(back) == a.String.ToLower();
                count++;
            }
            Report("limbs round trip of field operands (" + count + " values)", allOk && count > 0, "a round trip differed");
        }

        // Phase 4: SHA-256 of every sha256 vector, from its stored utf8 bytes and from its data string
        // through Utf8.Encode. One scratch buffer is reused for all calls.
        private void CheckSha256()
        {
            uint[] scratch = Sha256.NewScratch();
            Report("sha256 scratch length", scratch.Length == Sha256.ScratchLength, "got " + scratch.Length);

            byte[] digest = new byte[32];
            DataList list = GetList("sha256");
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                string name = entry["name"].String;
                string expected = entry["hash"].String;

                byte[] utf8 = Hex.Decode(entry["utf8"].String);
                if (utf8 == null)
                {
                    Report("sha256 bytes: " + name, false, "malformed utf8 field");
                }
                else
                {
                    Sha256.Hash(utf8, scratch, digest, 0);
                    string got = Hex.Encode(digest);
                    Report("sha256 bytes: " + name + " (" + utf8.Length + " bytes)", got == expected, "expected " + expected + ", got " + got);
                }

                string data = GetData(entry);
                if (data == null)
                {
                    Report("sha256 string: " + name, false, "missing or malformed utf16 field");
                    continue;
                }
                Sha256.Hash(Utf8.Encode(data), scratch, digest, 0);
                string gotString = Hex.Encode(digest);
                Report("sha256 string: " + name, gotString == expected, "expected " + expected + ", got " + gotString);
            }

            // Output at an offset leaves the surrounding bytes alone.
            byte[] wide = new byte[40];
            for (int i = 0; i < wide.Length; i++) wide[i] = 0xAA;
            Sha256.Hash(Hex.Decode("616263"), scratch, wide, 5);
            bool offsetOk = true;
            for (int i = 0; i < 5; i++) offsetOk &= wide[i] == 0xAA;
            for (int i = 37; i < 40; i++) offsetOk &= wide[i] == 0xAA;
            byte[] middle = new byte[32];
            System.Array.Copy(wide, 5, middle, 0, 32);
            offsetOk &= Hex.Encode(middle) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            Report("sha256 output at an offset", offsetOk, "digest or surrounding bytes wrong");
        }

        // Phase 5: field arithmetic mod p.
        private void CheckField()
        {
            CheckCompare();
            string[] ops = { "add", "sub", "mul", "sqr", "inv", "reduce" };
            CheckArithmetic("field", false, ops);
        }

        // Phase 6: scalar arithmetic mod n.
        private void CheckScalar()
        {
            CheckGeN();
            string[] ops = { "mul", "inv", "reduce" };
            CheckArithmetic("scalar", true, ops);
        }

        // Runs every case in a field or scalar vector list. Operands sit at odd offsets in one shared buffer.
        // Binary ops run three ways (separate result, result over a, result over b), unary ops two ways
        // (separate, in place), and the separate run also checks that the inputs were left alone. Square is
        // also checked against multiplying each mul operand by itself.
        private void CheckArithmetic(string listName, bool scalar, string[] ops)
        {
            uint[] buf = new uint[40];
            ulong[] t = new ulong[U256.ProductScratchLength];
            int slotA = 3;
            int slotB = 13;
            int slotR = 22;
            int slotTmp = 31;
            int[] cases = new int[ops.Length];
            int[] bad = new int[ops.Length];
            int sqrVsMul = 0;
            int sqrVsMulBad = 0;

            DataList list = GetList(listName);
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                string op = entry["op"].String;
                int opIndex = -1;
                for (int k = 0; k < ops.Length; k++)
                {
                    if (ops[k] == op) opIndex = k;
                }
                if (opIndex < 0)
                {
                    Report(listName + " case " + i, false, "unknown op " + op);
                    continue;
                }
                string a = entry["a"].String.ToLower();
                string expected = entry["result"].String.ToLower();
                DataToken bToken;
                string b = entry.TryGetValue("b", TokenType.String, out bToken) ? bToken.String.ToLower() : null;
                bool binary = op == "add" || op == "sub" || op == "mul";
                string label = listName + " " + op + "(" + a + (binary ? ", " + b : "") + ")";
                cases[opIndex]++;

                if (op == "reduce")
                {
                    if (!LoadLimbs(a, buf, slotR)) { bad[opIndex]++; Report(label, false, "malformed operand"); continue; }
                    if (scalar) U256.ScalarReduce(buf, slotR);
                    else U256.FieldReduce(buf, slotR);
                    string got = LimbsHex(buf, slotR);
                    if (got != expected) { bad[opIndex]++; Report(label, false, "expected " + expected + ", got " + got); }
                    continue;
                }

                if (!LoadLimbs(a, buf, slotA) || (binary && !LoadLimbs(b, buf, slotB)))
                {
                    bad[opIndex]++;
                    Report(label, false, "malformed operand");
                    continue;
                }

                // Separate result.
                ApplyArithmetic(op, scalar, buf, slotA, slotB, slotR, slotTmp, t);
                string sep = LimbsHex(buf, slotR);
                bool inputsKept = LimbsHex(buf, slotA) == a && (!binary || LimbsHex(buf, slotB) == b);

                // Result over a.
                LoadLimbs(a, buf, slotR);
                ApplyArithmetic(op, scalar, buf, slotR, slotB, slotR, slotTmp, t);
                string overA = LimbsHex(buf, slotR);

                // Result over b.
                string overB = expected;
                if (binary)
                {
                    LoadLimbs(b, buf, slotR);
                    ApplyArithmetic(op, scalar, buf, slotA, slotR, slotR, slotTmp, t);
                    overB = LimbsHex(buf, slotR);
                }

                if (sep != expected || overA != expected || overB != expected || !inputsKept)
                {
                    bad[opIndex]++;
                    Report(label, false, "expected " + expected + ", got " + sep + " / over a " + overA
                        + (binary ? " / over b " + overB : "") + (inputsKept ? "" : " (inputs modified)"));
                }

                if (op == "mul")
                {
                    ApplyArithmetic("mul", scalar, buf, slotA, slotA, slotR, slotTmp, t);
                    string mulSelf = LimbsHex(buf, slotR);
                    ApplyArithmetic("sqr", scalar, buf, slotA, slotA, slotR, slotTmp, t);
                    string sqrSelf = LimbsHex(buf, slotR);
                    sqrVsMul++;
                    if (sqrSelf != mulSelf)
                    {
                        sqrVsMulBad++;
                        Report(listName + " sqr(" + a + ") vs mul(a, a)", false, "sqr " + sqrSelf + ", mul " + mulSelf);
                    }
                }
            }

            for (int k = 0; k < ops.Length; k++)
            {
                if (cases[k] == 0) Report(listName + " " + ops[k], false, "no cases in vectors");
                else if (bad[k] == 0) Report(listName + " " + ops[k] + " (" + cases[k] + " cases)", true, "");
            }
            if (sqrVsMulBad == 0) Report(listName + " sqr(a) equals mul(a, a) (" + sqrVsMul + " operands)", sqrVsMul > 0, "no cases");
        }

        private void ApplyArithmetic(string op, bool scalar, uint[] buf, int ao, int bo, int ro, int tmpo, ulong[] t)
        {
            if (op == "add") U256.FieldAdd(buf, ao, buf, bo, buf, ro);
            else if (op == "sub") U256.FieldSub(buf, ao, buf, bo, buf, ro);
            else if (scalar)
            {
                if (op == "mul") U256.ScalarMul(buf, ao, buf, bo, buf, ro, t);
                else if (op == "sqr") U256.ScalarSqr(buf, ao, buf, ro, t);
                else if (op == "inv") U256.ScalarInv(buf, ao, buf, ro, buf, tmpo, t);
            }
            else
            {
                if (op == "mul") U256.FieldMul(buf, ao, buf, bo, buf, ro, t);
                else if (op == "sqr") U256.FieldSqr(buf, ao, buf, ro, t);
                else if (op == "inv") U256.FieldInv(buf, ao, buf, ro, buf, tmpo, t);
            }
        }

        // Phase 6: the >= n test, and scalar multiply on inputs that are not below n.
        private void CheckGeN()
        {
            uint[] buf = new uint[24];
            CheckGeNCase("n - 1 is below n", buf, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", false);
            CheckGeNCase("n is not below n", buf, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", true);
            CheckGeNCase("2^256 - 1 is not below n", buf, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", true);
            CheckGeNCase("p is not below n", buf, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", true);
            CheckGeNCase("limb 3 above n's is not below n", buf, "fffffffffffffffffffffffffffffffebaaedce7000000000000000000000000", true);
            CheckGeNCase("limb 3 below n's is below n", buf, "fffffffffffffffffffffffffffffffebaaedce5ffffffffffffffffffffffff", false);
            CheckGeNCase("limb 4 below n's is below n", buf, "fffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffff", false);

            // (2^256 - 1)² mod n and (n + 1)·(n + 2) mod n = 2: operands at and above n.
            ulong[] t = new ulong[U256.ProductScratchLength];
            LoadLimbs("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", buf, 0);
            U256.ScalarMul(buf, 0, buf, 0, buf, 8, t);
            string max = LimbsHex(buf, 8);
            string maxExpected = "9d671cd581c69bc5e697f5e45bcd07c3e972508f6d0e38f00911af2e084453c3";
            Report("scalar mul (2^256 - 1)^2", max == maxExpected, "expected " + maxExpected + ", got " + max);
            LoadLimbs("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142", buf, 0);
            LoadLimbs("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143", buf, 8);
            U256.ScalarMul(buf, 0, buf, 8, buf, 16, t);
            string small = LimbsHex(buf, 16);
            Report("scalar mul (n + 1)(n + 2) = 2", small == "0000000000000000000000000000000000000000000000000000000000000002", "got " + small);
        }

        private void CheckGeNCase(string name, uint[] buf, string a, bool expected)
        {
            LoadLimbs(a, buf, 0);
            Report("scalar " + name, U256.ScalarGeN(buf, 0) == expected, "wrong answer");
        }

        // Phase 5: Compare, IsZero and the >= p test on hand-picked values.
        private void CheckCompare()
        {
            uint[] buf = new uint[16];
            CheckCompareCase("compare 0 vs 1", buf, "00", "01", -1);
            CheckCompareCase("compare 1 vs 0", buf, "01", "00", 1);
            CheckCompareCase("compare equal", buf, "fffffffefffffc2f", "fffffffefffffc2f", 0);
            CheckCompareCase("compare top limb outranks low limbs", buf,
                "0100000000000000000000000000000000000000000000000000000000000000",
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 1);
            CheckCompareCase("compare differs in limb 0 only", buf,
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", -1);

            LoadLimbs("00", buf, 0);
            LoadLimbs("0100000000000000000000000000000000000000000000000000000000000000", buf, 8);
            Report("is zero", U256.IsZero(buf, 0) && !U256.IsZero(buf, 8), "wrong answer");

            CheckGeP("p - 1 is below p", buf, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", false);
            CheckGeP("p is not below p", buf, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", true);
            CheckGeP("2^256 - 1 is not below p", buf, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", true);
            CheckGeP("limb 1 above p's is not below p", buf, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000", true);
            CheckGeP("limb 1 below p's is below p", buf, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffff", false);
            CheckGeP("limb 2 below p's is below p", buf, "fffffffffffffffffffffffffffffffffffffffffffffffefffffffeffffffff", false);
        }

        private void CheckCompareCase(string name, uint[] buf, string a, string b, int expected)
        {
            LoadLimbs(a, buf, 0);
            LoadLimbs(b, buf, 8);
            int got = U256.Compare(buf, 0, buf, 8);
            Report(name, got == expected, "expected " + expected + ", got " + got);
        }

        private void CheckGeP(string name, uint[] buf, string a, bool expected)
        {
            LoadLimbs(a, buf, 0);
            Report("field " + name, U256.FieldGeP(buf, 0) == expected, "wrong answer");
        }

        // Phase 7: point doubling and addition, double multiplication and public key validation.
        private void CheckCurve()
        {
            uint[] s = Secp256k1.NewScratch();
            ulong[] t = new ulong[U256.ProductScratchLength];
            Report("curve scratch length", s.Length == Secp256k1.ScratchLength, "got " + s.Length);
            CheckPointOps(s, t);
            CheckPointVectors(s, t);
            CheckDoubleMulVectors(s, t);
            CheckPublicKeys(s, t);
        }

        // Double and add on small multiples of G, in and out of place, with the special cases.
        private void CheckPointOps(uint[] s, ulong[] t)
        {
            string g = FindPoint("G");
            string g2 = FindPoint("2G");
            string g3 = FindPoint("3G");
            string g7 = FindPoint("7G");
            string gNeg = FindPoint("(n-1)G = -G");

            // Points at 0, 24, 48, ...; affine G at 200.
            uint[] p = new uint[240];
            int pG = 0, p2 = 24, p3 = 48, p4 = 72, pR = 96, pInf = 120, pNeg = 144;
            int aG = 200;
            Secp256k1.FromAffine(s, Secp256k1.GOffset, p, pG);
            U256.Copy(s, Secp256k1.GOffset, p, aG);
            U256.Copy(s, Secp256k1.GOffset + 8, p, aG + 8);
            Secp256k1.SetInfinity(p, pInf);

            Report("curve G from scratch", PointHex(p, pG, s, t) == g, "got " + PointHex(p, pG, s, t));

            Secp256k1.Double(p, pG, p, p2, s, t);
            CheckPoint("curve double G = 2G", p, p2, g2, s, t);
            Secp256k1.Double(p, p2, p, p4, s, t);
            Secp256k1.CopyPoint(p, p2, p, pR);
            Secp256k1.Double(p, pR, p, pR, s, t);
            Report("curve double in place", PointHex(p, pR, s, t) == PointHex(p, p4, s, t), "differs from separate result");

            Secp256k1.AddAffine(p, p2, p, aG, p, p3, s, t);
            CheckPoint("curve 2G + G (mixed) = 3G", p, p3, g3, s, t);
            Secp256k1.Add(p, p2, p, pG, p, pR, s, t);
            CheckPoint("curve 2G + G (Jacobian) = 3G", p, pR, g3, s, t);
            Secp256k1.Add(p, pG, p, p2, p, pR, s, t);
            CheckPoint("curve G + 2G (Jacobian) = 3G", p, pR, g3, s, t);

            // 4G + 3G, both with Z != 1, separate and over either input.
            Secp256k1.Add(p, p4, p, p3, p, pR, s, t);
            CheckPoint("curve 4G + 3G = 7G", p, pR, g7, s, t);
            Secp256k1.CopyPoint(p, p4, p, pR);
            Secp256k1.Add(p, pR, p, p3, p, pR, s, t);
            CheckPoint("curve 4G + 3G over P = 7G", p, pR, g7, s, t);
            Secp256k1.CopyPoint(p, p3, p, pR);
            Secp256k1.Add(p, p4, p, pR, p, pR, s, t);
            CheckPoint("curve 4G + 3G over Q = 7G", p, pR, g7, s, t);

            // P == Q falls back to doubling, also when the two have different Z.
            Secp256k1.Add(p, p2, p, p2, p, pR, s, t);
            CheckPoint("curve 2G + 2G (same Z) = 4G", p, pR, PointHex(p, p4, s, t), s, t);
            // 3G again through the Jacobian path (G + 2G), which leaves Z negated relative to p3.
            Secp256k1.Add(p, pG, p, p2, p, pNeg, s, t);
            Secp256k1.Add(p, p3, p, pNeg, p, pR, s, t);
            CheckPoint("curve 3G + 3G (different Z) = 6G", p, pR, Double6(p, p3, s, t), s, t);
            Secp256k1.AddAffine(p, pG, p, aG, p, pR, s, t);
            CheckPoint("curve G + G (mixed) = 2G", p, pR, g2, s, t);

            // P == -Q gives infinity: negate Y of 3G (Z != 1) and of affine G.
            Secp256k1.CopyPoint(p, p3, p, pNeg);
            NegateY(p, pNeg + 8);
            Secp256k1.Add(p, p3, p, pNeg, p, pR, s, t);
            CheckPoint("curve 3G + (-3G) = infinity", p, pR, "infinity", s, t);
            U256.Copy(p, aG, p, 216);
            U256.Copy(p, aG + 8, p, 224);
            NegateY(p, 224);
            Secp256k1.FromAffine(p, 216, p, pNeg);
            CheckPoint("curve -G", p, pNeg, gNeg, s, t);
            Secp256k1.AddAffine(p, pG, p, 216, p, pR, s, t);
            CheckPoint("curve G + (-G) (mixed) = infinity", p, pR, "infinity", s, t);

            // Infinity on either side.
            Secp256k1.Add(p, pInf, p, p3, p, pR, s, t);
            CheckPoint("curve infinity + 3G = 3G", p, pR, g3, s, t);
            Secp256k1.Add(p, p3, p, pInf, p, pR, s, t);
            CheckPoint("curve 3G + infinity = 3G", p, pR, g3, s, t);
            Secp256k1.Add(p, pInf, p, pInf, p, pR, s, t);
            CheckPoint("curve infinity + infinity = infinity", p, pR, "infinity", s, t);
            Secp256k1.AddAffine(p, pInf, p, aG, p, pR, s, t);
            CheckPoint("curve infinity + G (mixed) = G", p, pR, g, s, t);
            Secp256k1.Double(p, pInf, p, pR, s, t);
            CheckPoint("curve double infinity = infinity", p, pR, "infinity", s, t);
        }

        private string Double6(uint[] p, int p3, uint[] s, ulong[] t)
        {
            uint[] tmp = new uint[Secp256k1.PointLength];
            Secp256k1.Double(p, p3, tmp, 0, s, t);
            return PointHex(tmp, 0, s, t);
        }

        // y -> p - y (y nonzero).
        private void NegateY(uint[] buf, int yo)
        {
            uint[] zero = new uint[8];
            U256.FieldSub(zero, 0, buf, yo, buf, yo);
        }

        // kG for every point vector, through u1 (G path) and through u2 with Q = G (Q path).
        private void CheckPointVectors(uint[] s, ulong[] t)
        {
            uint[] buf = new uint[72];
            int k = 0, zero = 8, q = 16, r = 32;
            U256.Copy(s, Secp256k1.GOffset, buf, q);
            U256.Copy(s, Secp256k1.GOffset + 8, buf, q + 8);
            DataList list = GetList("points");
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                string name = entry["name"].String;
                string expected = ExpectedPoint(entry);
                if (!LoadLimbs(entry["k"].String, buf, k))
                {
                    Report("point " + name, false, "malformed k");
                    continue;
                }
                Secp256k1.DoubleMul(buf, k, buf, zero, buf, q, buf, r, s, t);
                CheckPoint("point " + name + " = kG (via u1)", buf, r, expected, s, t);
                Secp256k1.DoubleMul(buf, zero, buf, k, buf, q, buf, r, s, t);
                CheckPoint("point " + name + " = kQ, Q = G (via u2)", buf, r, expected, s, t);
            }
        }

        // u1·G + u2·Q for every doubleMul vector, in one run and in uneven slices.
        private void CheckDoubleMulVectors(uint[] s, ulong[] t)
        {
            uint[] buf = new uint[72];
            int u1 = 0, u2 = 8, q = 16, r = 32;
            DataList list = GetList("doubleMul");
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                string name = "doubleMul " + entry["name"].String + " " + i;
                string expected = ExpectedPoint(entry);
                if (!LoadLimbs(entry["u1"].String, buf, u1) || !LoadLimbs(entry["u2"].String, buf, u2)
                    || !LoadLimbs(entry["qx"].String, buf, q) || !LoadLimbs(entry["qy"].String, buf, q + 8))
                {
                    Report(name, false, "malformed operand");
                    continue;
                }
                Secp256k1.DoubleMul(buf, u1, buf, u2, buf, q, buf, r, s, t);
                CheckPoint(name, buf, r, expected, s, t);

                Secp256k1.DoubleMulInit(buf, q, s, t);
                int bit = 255;
                int[] slices = { 1, 30, 7, 100, 64, 54 };
                for (int j = 0; j < slices.Length; j++)
                {
                    Secp256k1.DoubleMulBits(buf, u1, buf, u2, bit, slices[j], s, t);
                    bit -= slices[j];
                }
                CheckPoint(name + " (sliced)", s, Secp256k1.AccumulatorOffset, bit == -1 ? expected : "slices do not cover 256 bits", s, t);
            }
        }

        // Every public key case, and that a valid key loads to its own coordinates.
        private void CheckPublicKeys(uint[] s, ulong[] t)
        {
            uint[] key = new uint[20];
            DataList list = GetList("publicKeys");
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                string name = entry["name"].String;
                string hex = entry["publicKey"].String;
                bool expected = entry["valid"].Boolean;
                for (int j = 0; j < key.Length; j++) key[j] = 0xA5A5A5A5u;
                bool got = Secp256k1.LoadPublicKey(hex, key, 2, s, t);
                if (got != expected)
                {
                    Report("public key " + name, false, "expected " + (expected ? "valid" : "invalid"));
                    continue;
                }
                bool untouched = key[0] == 0xA5A5A5A5u && key[1] == 0xA5A5A5A5u && key[18] == 0xA5A5A5A5u && key[19] == 0xA5A5A5A5u;
                if (got)
                {
                    string coords = LimbsHex(key, 2) + LimbsHex(key, 10);
                    Report("public key " + name, untouched && "04" + coords == hex.ToLower(), "loaded coordinates differ");
                }
                else
                {
                    bool keptAll = untouched;
                    for (int j = 2; j < 18; j++) keptAll &= key[j] == 0xA5A5A5A5u;
                    Report("public key " + name + " rejected", keptAll, "wrote to the result");
                }
            }
            Report("public key null rejected", !Secp256k1.LoadPublicKey(null, key, 2, s, t), "accepted");
        }

        // Phase 8: blocking ECDSA verification, through the static core with each entry's own key, and through
        // the SignatureVerifier behaviour for entries signed against the test public key.
        // Split over steps (BeginEcdsa, one CheckSignatureEntry per case, EndEcdsa) to stay within Udon's time limit.
        private uint[] ecdsaScratch;
        private ulong[] ecdsaProduct;
        private uint[] ecdsaSha;
        private int signaturesViaVerifier;
        private int flipsViaVerifier;

        private void BeginEcdsa()
        {
            ecdsaScratch = Secp256k1.NewScratch();
            ecdsaProduct = new ulong[U256.ProductScratchLength];
            ecdsaSha = Sha256.NewScratch();
            signaturesViaVerifier = 0;
            flipsViaVerifier = 0;
            CheckEcdsaHelpers();
            CheckHashVectors(ecdsaScratch, ecdsaProduct);
        }

        private void EndEcdsa()
        {
            ReportViaVerifier("signatures", signaturesViaVerifier);
            ReportViaVerifier("signatureFlips", flipsViaVerifier);
            CheckVerifierEdges(ecdsaScratch, ecdsaProduct, ecdsaSha);
        }

        private void ReportViaVerifier(string listName, int count)
        {
            Report("ecdsa " + listName + " ran through SignatureVerifier (" + count + " cases)", verifier != null && count > 0,
                verifier == null ? "no verifier assigned" : "no entry uses the test public key");
        }

        // Hex.DecodeLimbs, Hex.IsHex and U256.AddN, which the signature parser and the final comparison use.
        private void CheckEcdsaHelpers()
        {
            string value = "0123456789abcdefFEDCBA9876543210fedcba98765432100123456789ABCDEF";
            uint[] buf = new uint[18];
            bool decoded = Hex.DecodeLimbs("zz" + value, 2, buf, 1);
            Report("hex decode limbs at offsets", decoded && LimbsHex(buf, 1) == value.ToLower() && buf[0] == 0u && buf[9] == 0u,
                "got " + LimbsHex(buf, 1));
            Report("hex decode limbs rejects non-hex", !Hex.DecodeLimbs(value.Substring(0, 63) + "g", 0, buf, 0), "accepted");
            Report("hex is hex", Hex.IsHex("x0aFx", 1, 3) && !Hex.IsHex("x0aFx", 1, 4) && Hex.IsHex("", 0, 0), "wrong answer");

            string n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
            LoadLimbs("0000000000000000000000000000000000000000000000000000000000000001", buf, 0);
            bool fits = U256.AddN(buf, 0, buf, 8);
            Report("scalar add n: 1 + n", fits && LimbsHex(buf, 8) == "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
                "got " + LimbsHex(buf, 8));
            // 2^256 - n = 14551231950b75fc4402da1732fc9bebf: the smallest value whose sum overflows.
            LoadLimbs("000000000000000000000000000000014551231950b75fc4402da1732fc9bebe", buf, 0);
            fits = U256.AddN(buf, 0, buf, 0);
            Report("scalar add n: largest that fits (in place)", fits && LimbsHex(buf, 0) == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "got " + LimbsHex(buf, 0));
            LoadLimbs("000000000000000000000000000000014551231950b75fc4402da1732fc9bebf", buf, 0);
            Report("scalar add n: smallest that overflows", !U256.AddN(buf, 0, buf, 8) && U256.IsZero(buf, 8), "got " + LimbsHex(buf, 8));
            LoadLimbs(n, buf, 0);
            Report("scalar add n: n + n overflows", !U256.AddN(buf, 0, buf, 8), "fit");
        }

        private void CheckHashVectors(uint[] s, ulong[] t)
        {
            uint[] key = new uint[Secp256k1.AffineLength];
            DataList list = GetList("hashVectors");
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                string name = "ecdsa hash: " + entry["name"].String;
                bool expected = entry["valid"].Boolean;
                byte[] hash = Hex.Decode(entry["hash"].String);
                if (hash == null || hash.Length != 32 || !Secp256k1.LoadPublicKey(entry["publicKey"].String, key, 0, s, t))
                {
                    Report(name, false, "malformed hash or public key");
                    continue;
                }
                bool got = Secp256k1.VerifyHash(hash, 0, entry["signature"].String, key, 0, s, t);
                Report(name, got == expected, "expected " + (expected ? "valid" : "invalid"));

                // The same hash at an offset inside a larger buffer.
                byte[] shifted = new byte[40];
                for (int j = 0; j < 32; j++) shifted[j + 5] = hash[j];
                got = Secp256k1.VerifyHash(shifted, 5, entry["signature"].String, key, 0, s, t);
                Report(name + " (hash at an offset)", got == expected, "expected " + (expected ? "valid" : "invalid"));
            }
        }

        // One signature case: through the static core with the entry's own key, and through SignatureVerifier
        // (Verify and VerifyHash) when the entry uses the test public key.
        private void CheckSignatureEntry(string listName, int i)
        {
            uint[] s = ecdsaScratch;
            ulong[] t = ecdsaProduct;
            uint[] key = new uint[Secp256k1.AffineLength];
            byte[] hash = new byte[32];
            DataDictionary entry = GetList(listName)[i].DataDictionary;
            string name = "ecdsa " + listName + ": " + entry["name"].String;
            bool expected = entry["valid"].Boolean;
            string expectedText = expected ? "valid" : "invalid";
            string data = GetData(entry);
            string publicKey = entry["publicKey"].String;
            string signature = entry["signature"].String;
            if (data == null || !Secp256k1.LoadPublicKey(publicKey, key, 0, s, t))
            {
                Report(name, false, "malformed data or public key");
                return;
            }

            Sha256.Hash(Utf8.Encode(data), ecdsaSha, hash, 0);
            bool got = Secp256k1.VerifyHash(hash, 0, signature, key, 0, s, t);
            Report(name, got == expected, "expected " + expectedText);

            if (verifier != null && publicKey.ToLower() == root["testPublicKey"].String)
            {
                if (listName == "signatures") signaturesViaVerifier++;
                else flipsViaVerifier++;
                Report(name + " (SignatureVerifier.Verify)", verifier.Verify(data, signature) == expected, "expected " + expectedText);
                Report(name + " (SignatureVerifier.VerifyHash)", verifier.VerifyHash(hash, signature) == expected, "expected " + expectedText);
            }
        }

        // Inputs the vectors cannot express (null, short hashes) and the verifiers' key handling.
        private void CheckVerifierEdges(uint[] s, ulong[] t, uint[] sha)
        {
            DataList list = GetList("signatures");
            DataDictionary entry = list[0].DataDictionary;
            string data = GetData(entry);
            string signature = entry["signature"].String;
            bool baseValid = entry["valid"].Boolean;
            Report("ecdsa edge cases use a valid signature", baseValid && data != null, "first signature entry is not valid");

            uint[] key = new uint[Secp256k1.AffineLength];
            byte[] hash = new byte[32];
            Secp256k1.LoadPublicKey(entry["publicKey"].String, key, 0, s, t);
            Sha256.Hash(Utf8.Encode(data), sha, hash, 0);
            Report("ecdsa core: null hash rejected", !Secp256k1.VerifyHash(null, 0, signature, key, 0, s, t), "accepted");
            Report("ecdsa core: 31-byte hash rejected", !Secp256k1.VerifyHash(new byte[31], 0, signature, key, 0, s, t), "accepted");
            Report("ecdsa core: hash past the buffer end rejected", !Secp256k1.VerifyHash(hash, 1, signature, key, 0, s, t), "accepted");
            Report("ecdsa core: negative hash offset rejected", !Secp256k1.VerifyHash(hash, -1, signature, key, 0, s, t), "accepted");
            Report("ecdsa core: null signature rejected", !Secp256k1.VerifyHash(hash, 0, null, key, 0, s, t), "accepted");
            Report("ecdsa core: valid again after rejections", Secp256k1.VerifyHash(hash, 0, signature, key, 0, s, t), "rejected");

            if (verifier == null)
            {
                Report("ecdsa SignatureVerifier assigned", false, "no verifier assigned");
            }
            else
            {
                Report("ecdsa SignatureVerifier key is valid", verifier.IsKeyValid(), "rejected the test public key");
                Report("ecdsa SignatureVerifier: null data rejected", !verifier.Verify(null, signature), "accepted");
                Report("ecdsa SignatureVerifier: null signature rejected", !verifier.Verify(data, null), "accepted");
                Report("ecdsa SignatureVerifier: null hash rejected", !verifier.VerifyHash(null, signature), "accepted");
                Report("ecdsa SignatureVerifier: 31-byte hash rejected", !verifier.VerifyHash(new byte[31], signature), "accepted");
                byte[] longHash = new byte[33];
                for (int j = 0; j < 32; j++) longHash[j] = hash[j];
                Report("ecdsa SignatureVerifier: 33-byte hash rejected", !verifier.VerifyHash(longHash, signature), "accepted");
                Report("ecdsa SignatureVerifier: valid again after rejections", verifier.Verify(data, signature), "rejected");
            }

            if (invalidKeyVerifier == null)
            {
                Report("ecdsa invalid-key SignatureVerifier assigned", false, "no verifier assigned");
            }
            else
            {
                Report("ecdsa invalid-key SignatureVerifier: key rejected", !invalidKeyVerifier.IsKeyValid(), "accepted");
                Report("ecdsa invalid-key SignatureVerifier: Verify fails", !invalidKeyVerifier.Verify(data, signature), "accepted");
                Report("ecdsa invalid-key SignatureVerifier: VerifyHash fails", !invalidKeyVerifier.VerifyHash(hash, signature), "accepted");
            }
        }

        // Phase 9: the sliced building blocks against their one-call versions.
        private void CheckSlicedPrimitives()
        {
            uint[] sha = Sha256.NewScratch();
            byte[] digest = new byte[32];
            DataList list = GetList("sha256");
            int sliceSizes = 0;
            bool shaOk = true;
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                byte[] utf8 = Hex.Decode(entry["utf8"].String);
                if (utf8 == null) continue;
                int blocks = Sha256.BlockCount(utf8.Length);
                for (int size = 1; size <= 3; size += 2)
                {
                    Sha256.Begin(sha);
                    for (int b = 0; b < blocks; b += size) Sha256.ProcessBlocks(utf8, b, Mathf.Min(size, blocks - b), sha);
                    Sha256.Finish(sha, digest, 0);
                    shaOk &= Hex.Encode(digest) == entry["hash"].String;
                    sliceSizes++;
                }
            }
            Report("sha256 in slices of 1 and 3 blocks (" + sliceSizes + " runs)", shaOk && sliceSizes > 0, "a digest differed");

            uint[] buf = new uint[32];
            ulong[] t = new ulong[U256.ProductScratchLength];
            string[] values =
            {
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "c343df2ce4839762e0be9c9bfd1cf0b0aabebe8efaa364df305781877d83dd26"
            };
            for (int i = 0; i < values.Length; i++)
            {
                LoadLimbs(values[i], buf, 0);
                U256.ScalarInv(buf, 0, buf, 8, buf, 16, t);
                U256.ScalarInvBegin(buf, 0, buf, 24, buf, 16);
                for (int bit = 255; bit >= 0; bit -= 7) U256.ScalarInvBits(buf, 24, buf, 16, bit, Mathf.Min(7, bit + 1), t);
                Report("scalar inv in slices of 7 bits: " + values[i], LimbsHex(buf, 8) == LimbsHex(buf, 24),
                    "one call " + LimbsHex(buf, 8) + ", sliced " + LimbsHex(buf, 24));
            }
        }

        // Phase 9: requests through SignatureVerifier.RequestVerify. Round 0 queues every test-key signature case
        // (more than the queue holds, so some submissions are refused and retried) plus malformed inputs, at the
        // verifier's own iterationsPerFrame; round 1 queues a few cases at 7 iterations per frame, which divides
        // neither 256 nor the hash and inverse slices evenly. Results must arrive once each, in request order.
        private const int SlicedIdBase = 1000;
        private string[] slicedName;
        private string[] slicedData;
        private string[] slicedSignature;
        private bool[] slicedExpected;
        private int[] slicedGot;
        private int slicedCount;
        private int slicedNext;
        private int slicedReceived;
        private int slicedLastId;
        private bool slicedOrderOk;
        private bool slicedIdsOk;
        private int slicedRefused;
        private bool slicedRefusedWhileFull;
        private int slicedRound;
        private int slicedIterations;
        private int originalIterations;
        private bool slicedBlockingChecked;
        private bool invalidKeyPending;
        private int slicedFullRuns;
        private int slicedMinFrames;
        private int slicedMaxFrames;
        private double slicedMaxComputeMs;
        private double slicedMaxMeanSliceMs;
        private double slicedMaxSliceMs;

        private void BeginSliced(int round)
        {
            slicedRound = round;
            if (verifier == null)
            {
                Report("sliced: SignatureVerifier assigned", false, "no verifier assigned");
                slicedCount = 0;
                return;
            }
            if (round == 0) originalIterations = verifier.iterationsPerFrame;
            else verifier.iterationsPerFrame = 7;
            slicedIterations = verifier.iterationsPerFrame;

            int capacity = GetList("signatures").Count + GetList("signatureFlips").Count + 3;
            slicedName = new string[capacity];
            slicedData = new string[capacity];
            slicedSignature = new string[capacity];
            slicedExpected = new bool[capacity];
            slicedGot = new int[capacity];
            slicedCount = 0;
            AddSlicedEntries("signatures", round == 0 ? 1000 : 6);
            if (round == 0)
            {
                AddSlicedEntries("signatureFlips", 1000);
                string signature = slicedSignature[0];
                AddSlicedCase("null data", null, signature, false);
                AddSlicedCase("null signature", "x", null, false);
                AddSlicedCase("malformed signature", "x", "zz", false);
            }
            slicedNext = 0;
            slicedReceived = 0;
            slicedLastId = SlicedIdBase - 1;
            slicedOrderOk = true;
            slicedIdsOk = true;
            slicedRefused = 0;
            slicedRefusedWhileFull = true;
            slicedBlockingChecked = round != 0;
            slicedFullRuns = 0;
            slicedMinFrames = int.MaxValue;
            slicedMaxFrames = 0;
            slicedMaxComputeMs = 0;
            slicedMaxMeanSliceMs = 0;
            slicedMaxSliceMs = 0;

            if (round == 0)
            {
                Report("sliced: null caller refused", !verifier.RequestVerify("x", slicedSignature[0], null, nameof(_OnSlicedResult), 1), "accepted");
                Report("sliced: empty callback event refused", !verifier.RequestVerify("x", slicedSignature[0], this, "", 1), "accepted");
                Report("sliced: null callback event refused", !verifier.RequestVerify("x", slicedSignature[0], this, null, 1), "accepted");
                invalidKeyPending = invalidKeyVerifier != null
                    && invalidKeyVerifier.RequestVerify(slicedData[0], slicedSignature[0], this, nameof(_OnInvalidKeyResult), 77);
                Report("sliced: invalid-key verifier accepts the request", invalidKeyPending, "refused");
            }
            SubmitSliced();
        }

        private void AddSlicedEntries(string listName, int most)
        {
            DataList list = GetList(listName);
            string testKey = root["testPublicKey"].String;
            int added = 0;
            for (int i = 0; i < list.Count && added < most; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                if (entry["publicKey"].String.ToLower() != testKey) continue;
                string data = GetData(entry);
                if (data == null) continue;
                AddSlicedCase(listName + ": " + entry["name"].String, data, entry["signature"].String, entry["valid"].Boolean);
                added++;
            }
        }

        private void AddSlicedCase(string name, string data, string signature, bool expected)
        {
            slicedName[slicedCount] = name;
            slicedData[slicedCount] = data;
            slicedSignature[slicedCount] = signature;
            slicedExpected[slicedCount] = expected;
            slicedGot[slicedCount] = 0;
            slicedCount++;
        }

        // Queues as many of the round's cases as the verifier takes.
        private void SubmitSliced()
        {
            while (slicedNext < slicedCount)
            {
                if (!verifier.RequestVerify(slicedData[slicedNext], slicedSignature[slicedNext], this, nameof(_OnSlicedResult), SlicedIdBase + slicedNext))
                {
                    slicedRefused++;
                    if (verifier.PendingCount() < verifier.queueCapacity) slicedRefusedWhileFull = false;
                    return;
                }
                slicedNext++;
            }
        }

        // True while the round still waits for results.
        private bool SlicedPending()
        {
            if (verifier == null) return false;
            SubmitSliced();
            if (!slicedBlockingChecked && verifier.PendingCount() > 0)
            {
                // The blocking path has its own buffers: using it mid-request must not disturb the sliced one.
                slicedBlockingChecked = true;
                Report("sliced: blocking Verify while requests are pending", verifier.Verify(slicedData[0], slicedSignature[0]) == slicedExpected[0],
                    "wrong result");
            }
            if (runAllMode)
            {
                verifier.ProcessAllNow();
                if (invalidKeyVerifier != null) invalidKeyVerifier.ProcessAllNow();
            }
            return slicedReceived < slicedCount || slicedNext < slicedCount || (slicedRound == 0 && invalidKeyPending);
        }

        public void _OnSlicedResult()
        {
            int id = verifier.resultRequestId;
            bool valid = verifier.resultValid;
            int i = id - SlicedIdBase;
            if (i < 0 || i >= slicedCount || slicedGot[i] != 0)
            {
                slicedIdsOk = false;
                return;
            }
            if (id <= slicedLastId) slicedOrderOk = false;
            slicedLastId = id;
            slicedGot[i] = valid ? 1 : 2;
            slicedReceived++;
            Report("ecdsa sliced (" + slicedIterations + " per frame) " + slicedName[i], valid == slicedExpected[i],
                "expected " + (slicedExpected[i] ? "valid" : "invalid"));

            if (verifier.lastMaxFrameMs > slicedMaxSliceMs) slicedMaxSliceMs = verifier.lastMaxFrameMs;
            if (valid)
            {
                // A valid result ran every stage, so its frames and time are those of a full verification.
                slicedFullRuns++;
                if (verifier.lastFrames < slicedMinFrames) slicedMinFrames = verifier.lastFrames;
                if (verifier.lastFrames > slicedMaxFrames) slicedMaxFrames = verifier.lastFrames;
                if (verifier.lastComputeMs > slicedMaxComputeMs) slicedMaxComputeMs = verifier.lastComputeMs;
                double mean = verifier.lastComputeMs / verifier.lastFrames;
                if (mean > slicedMaxMeanSliceMs) slicedMaxMeanSliceMs = mean;
            }
        }

        public void _OnInvalidKeyResult()
        {
            invalidKeyPending = false;
            Report("sliced: invalid-key verifier reports invalid", invalidKeyVerifier.resultRequestId == 77 && !invalidKeyVerifier.resultValid,
                "got id " + invalidKeyVerifier.resultRequestId + ", valid " + invalidKeyVerifier.resultValid);
        }

        private void EndSlicedRound()
        {
            if (verifier == null) return;
            string round = "sliced round " + slicedRound + " (" + slicedIterations + " per frame, " + slicedCount + " requests)";
            Report(round + ": every result arrived once", slicedIdsOk && slicedReceived == slicedCount, "got " + slicedReceived + (slicedIdsOk ? "" : ", unknown or repeated IDs"));
            Report(round + ": results in request order", slicedOrderOk, "out of order");
            Report(round + ": verifier idle afterwards", verifier.PendingCount() == 0, verifier.PendingCount() + " pending");
            if (slicedRound == 0)
            {
                Report(round + ": a full queue refused requests", slicedRefused > 0 && slicedRefusedWhileFull,
                    slicedRefused == 0 ? "never full" : "refused while not full");
            }
            Debug.Log("[VectorTests] timing " + round + ": full verification " + slicedMinFrames + " to " + slicedMaxFrames + " frames, at most "
                + slicedMaxComputeMs.ToString("F1") + " ms of computation, mean slice at most " + slicedMaxMeanSliceMs.ToString("F2")
                + " ms, longest slice " + slicedMaxSliceMs.ToString("F2") + " ms (" + slicedFullRuns + " full runs)");
        }

        private void EndSliced()
        {
            if (verifier != null) verifier.iterationsPerFrame = originalIterations;
        }

        private string FindPoint(string name)
        {
            DataList list = GetList("points");
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                if (entry["name"].String == name) return ExpectedPoint(entry);
            }
            return "missing point vector " + name;
        }

        private string ExpectedPoint(DataDictionary entry)
        {
            if (entry["infinity"].Boolean) return "infinity";
            return entry["x"].String.ToLower() + "," + entry["y"].String.ToLower();
        }

        // "x,y" in lowercase hex (affine), or "infinity".
        private string PointHex(uint[] p, int po, uint[] s, ulong[] t)
        {
            uint[] a = new uint[Secp256k1.AffineLength];
            if (!Secp256k1.ToAffine(p, po, a, 0, s, t)) return "infinity";
            return LimbsHex(a, 0) + "," + LimbsHex(a, 8);
        }

        private void CheckPoint(string name, uint[] p, int po, string expected, uint[] s, ulong[] t)
        {
            string got = PointHex(p, po, s, t);
            Report(name, got == expected, "expected " + expected + ", got " + got);
        }

        // Up to 64 hex chars (left-padded with zeros) -> 8 limbs at dst[offset..].
        private bool LoadLimbs(string hex, uint[] dst, int offset)
        {
            if (hex == null || hex.Length > 64) return false;
            byte[] bytes = Hex.Decode(hex.PadLeft(64, '0'));
            if (bytes == null) return false;
            U256.FromBytes(bytes, 0, dst, offset);
            return true;
        }

        private string LimbsHex(uint[] src, int offset)
        {
            byte[] bytes = new byte[32];
            U256.ToBytes(src, offset, bytes, 0);
            return Hex.Encode(bytes);
        }

        private DataList GetList(string name)
        {
            DataToken list;
            if (root.TryGetValue(name, TokenType.DataList, out list)) return list.DataList;
            return new DataList();
        }

        private string FindString(DataList list, string entryName, string key)
        {
            for (int i = 0; i < list.Count; i++)
            {
                DataDictionary entry = list[i].DataDictionary;
                if (entry["name"].String == entryName) return entry[key].String;
            }
            return null;
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
