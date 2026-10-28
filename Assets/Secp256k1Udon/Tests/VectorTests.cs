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
                CheckHex();
                CheckUtf8();
                CheckLimbs();
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
