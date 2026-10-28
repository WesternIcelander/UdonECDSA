using UdonSharp;
using UnityEngine;
using VRC.SDKBase;

namespace Secp256k1Udon
{
    // Verifies that a string was signed by the authority whose public key is set in the inspector:
    // ECDSA over secp256k1 of SHA-256(UTF-8 bytes of data), with the signature as 130 hex chars r || s || v
    // (either case; v is ignored). The data is opaque: it is hashed, never parsed.
    //
    // The key is validated once, at Start or on first use, whichever comes first. An invalid key logs an
    // error and makes every verification return false.
    //
    // Two ways to verify:
    // - Verify / VerifyHash: blocking, about 300 ms in one frame.
    // - RequestVerify: frame-sliced. Requests wait in a fixed-capacity queue and run one at a time, a slice per
    //   frame, so no frame spends much more than iterationsPerFrame double-and-add steps on it. When a request
    //   is done, resultRequestId and resultValid are set on this verifier and callbackEvent is sent to the
    //   caller, which reads them in that event (the next request overwrites them).
    // The two use separate buffers, so a blocking call in the middle of a sliced request is safe.
    // The verifier's GameObject must stay active while requests are pending.
    [UdonBehaviourSyncMode(BehaviourSyncMode.None)]
    public class SignatureVerifier : UdonSharpBehaviour
    {
        [Tooltip("Authority public key, uncompressed: 04 || x || y as 130 hex characters (either case).")]
        public string publicKeyHex;

        [Tooltip("Double-and-add steps per frame for RequestVerify (256 per verification, about 1 ms each on desktop). "
            + "Hashing and the scalar inverse are sliced to a similar cost per frame.")]
        public int iterationsPerFrame = 1;

        [Tooltip("Most RequestVerify requests waiting at once, besides the one running. RequestVerify returns false "
            + "and never calls back when the queue is full.")]
        public int queueCapacity = 16;

        // Result of the request that just finished, valid while its callback event runs.
        [HideInInspector] public int resultRequestId;
        [HideInInspector] public bool resultValid;

        // Measurements of the last finished request: frames it took (slices), total computation time and the
        // longest slice, in milliseconds. Callback time is not included.
        [HideInInspector] public int lastFrames;
        [HideInInspector] public double lastComputeMs;
        [HideInInspector] public double lastMaxFrameMs;

        // Slices of the hash and of the scalar inverse cost about this much less than a double-and-add step.
        private const int HashBlocksPerIteration = 4;
        private const int InverseBitsPerIteration = 6;

        private const int StageIdle = 0;
        private const int StageHash = 1;
        private const int StageInverse = 2;
        private const int StageSetupEnd = 3;
        private const int StageLoop = 4;
        private const int StageFinish = 5;

        private bool initialized;
        private bool keyValid;
        private uint[] key;

        // Blocking path.
        private uint[] curveScratch;
        private ulong[] product;
        private uint[] shaScratch;
        private byte[] hash;

        // Sliced path.
        private uint[] sliceCurve;
        private ulong[] sliceProduct;
        private uint[] sliceSha;
        private byte[] sliceHash;

        // Queue, a ring buffer.
        private string[] queueData;
        private string[] queueSignature;
        private UdonSharpBehaviour[] queueCaller;
        private string[] queueEvent;
        private int[] queueId;
        private int queueHead;
        private int queueCount;

        // The running request.
        private int stage;
        private string currentSignature;
        private UdonSharpBehaviour currentCaller;
        private string currentEvent;
        private int currentId;
        private byte[] message;
        private int block;
        private int blocks;
        private int bit;
        private bool ticking;
        private System.Diagnostics.Stopwatch sliceWatch;
        private int frames;
        private double computeMs;
        private double maxFrameMs;

        private void Start()
        {
            Initialize();
        }

        public bool IsKeyValid()
        {
            Initialize();
            return keyValid;
        }

        // Blocking verification of data against signatureHex. Takes a long frame; see RequestVerify for calls
        // during play. Returns false for any malformed input (null included) and never throws.
        public bool Verify(string data, string signatureHex)
        {
            Initialize();
            if (!keyValid || data == null) return false;
            Sha256.Hash(Utf8.Encode(data), shaScratch, hash, 0);
            return Secp256k1.VerifyHash(hash, 0, signatureHex, key, 0, curveScratch, product);
        }

        // Blocking verification of a precomputed 32-byte message hash, used directly as z.
        public bool VerifyHash(byte[] hash32, string signatureHex)
        {
            Initialize();
            if (!keyValid || hash32 == null || hash32.Length != 32) return false;
            return Secp256k1.VerifyHash(hash32, 0, signatureHex, key, 0, curveScratch, product);
        }

        // Frame-sliced verification of data against signatureHex. Queues the request and returns true; when it is
        // done (a few seconds later, after the requests queued before it), sets resultRequestId = requestId and
        // resultValid, then sends callbackEvent to caller. Malformed input (null data, a bad signature, an
        // invalid key) is accepted here and reported invalid through the callback.
        //
        // Returns false, and never calls back, when the queue is full (queueCapacity requests) or when caller is
        // null or callbackEvent is null or empty. The caller's event must be public; a caller destroyed in the
        // meantime is skipped.
        public bool RequestVerify(string data, string signatureHex, UdonSharpBehaviour caller, string callbackEvent, int requestId)
        {
            Initialize();
            if (caller == null || string.IsNullOrEmpty(callbackEvent)) return false;
            if (queueCount >= queueData.Length) return false;
            int slot = (queueHead + queueCount) % queueData.Length;
            queueData[slot] = data;
            queueSignature[slot] = signatureHex;
            queueCaller[slot] = caller;
            queueEvent[slot] = callbackEvent;
            queueId[slot] = requestId;
            queueCount++;
            if (!ticking)
            {
                ticking = true;
                SendCustomEventDelayedFrames(nameof(_Tick), 1);
            }
            return true;
        }

        // Requests waiting or running.
        public int PendingCount()
        {
            return queueCount + (stage != StageIdle ? 1 : 0);
        }

        // Runs every pending request to completion now, callbacks included, in one long frame. For tests and
        // tooling (and the EditMode tests, where delayed events do not run).
        public void ProcessAllNow()
        {
            Initialize();
            while (stage != StageIdle || queueCount > 0) RunSlice();
        }

        // One slice per frame while requests are pending. Public only so the delayed event can reach it.
        public void _Tick()
        {
            ticking = false;
            if (stage == StageIdle && queueCount == 0) return;
            RunSlice();
            if (stage != StageIdle || queueCount > 0)
            {
                ticking = true;
                SendCustomEventDelayedFrames(nameof(_Tick), 1);
            }
        }

        // Starts the next request, or runs one slice of the running one. A finished request's callback is the
        // last thing in its slice.
        private void RunSlice()
        {
            sliceWatch = System.Diagnostics.Stopwatch.StartNew();
            if (stage == StageIdle)
            {
                StartRequest();
                if (stage == StageIdle) return;
                EndSlice();
                return;
            }

            int n = iterationsPerFrame < 1 ? 1 : iterationsPerFrame;
            if (stage == StageHash)
            {
                int count = Mathf.Min(n * HashBlocksPerIteration, blocks - block);
                Sha256.ProcessBlocks(message, block, count, sliceSha);
                block += count;
                if (block == blocks)
                {
                    message = null;
                    Sha256.Finish(sliceSha, sliceHash, 0);
                    Secp256k1.VerifySetupBegin(sliceHash, 0, sliceCurve);
                    bit = 255;
                    stage = StageInverse;
                }
            }
            else if (stage == StageInverse)
            {
                int count = Mathf.Min(n * InverseBitsPerIteration, bit + 1);
                Secp256k1.VerifyInverseBits(bit, count, sliceCurve, sliceProduct);
                bit -= count;
                if (bit < 0) stage = StageSetupEnd;
            }
            else if (stage == StageSetupEnd)
            {
                Secp256k1.VerifySetupEnd(key, 0, sliceCurve, sliceProduct);
                bit = 255;
                stage = StageLoop;
            }
            else if (stage == StageLoop)
            {
                int count = Mathf.Min(n, bit + 1);
                Secp256k1.DoubleMulBits(sliceCurve, Secp256k1.U1Offset, sliceCurve, Secp256k1.U2Offset, bit, count, sliceCurve, sliceProduct);
                bit -= count;
                if (bit < 0) stage = StageFinish;
            }
            else
            {
                Complete(Secp256k1.VerifyFinish(sliceCurve, sliceProduct));
                return;
            }
            EndSlice();
        }

        // Takes the next request off the queue: checks the key and data, parses the signature (rejecting it at
        // once when malformed), encodes the data and starts the hash.
        private void StartRequest()
        {
            int slot = queueHead;
            string data = queueData[slot];
            currentSignature = queueSignature[slot];
            currentCaller = queueCaller[slot];
            currentEvent = queueEvent[slot];
            currentId = queueId[slot];
            queueData[slot] = null;
            queueSignature[slot] = null;
            queueCaller[slot] = null;
            queueEvent[slot] = null;
            queueHead = (queueHead + 1) % queueData.Length;
            queueCount--;
            frames = 0;
            computeMs = 0;
            maxFrameMs = 0;

            if (!keyValid || data == null || !Secp256k1.VerifyParse(currentSignature, sliceCurve))
            {
                Complete(false);
                return;
            }
            message = Utf8.Encode(data);
            Sha256.Begin(sliceSha);
            block = 0;
            blocks = Sha256.BlockCount(message.Length);
            stage = StageHash;
        }

        private void EndSlice()
        {
            sliceWatch.Stop();
            double ms = sliceWatch.Elapsed.TotalMilliseconds;
            frames++;
            computeMs += ms;
            if (ms > maxFrameMs) maxFrameMs = ms;
        }

        private void Complete(bool valid)
        {
            EndSlice();
            stage = StageIdle;
            message = null;
            lastFrames = frames;
            lastComputeMs = computeMs;
            lastMaxFrameMs = maxFrameMs;
            resultRequestId = currentId;
            resultValid = valid;
            UdonSharpBehaviour caller = currentCaller;
            string callbackEvent = currentEvent;
            currentCaller = null;
            currentEvent = null;
            currentSignature = null;
            if (Utilities.IsValid(caller)) caller.SendCustomEvent(callbackEvent);
        }

        private void Initialize()
        {
            if (initialized) return;
            initialized = true;
            key = new uint[Secp256k1.AffineLength];
            curveScratch = Secp256k1.NewScratch();
            product = new ulong[U256.ProductScratchLength];
            shaScratch = Sha256.NewScratch();
            hash = new byte[32];
            sliceCurve = Secp256k1.NewScratch();
            sliceProduct = new ulong[U256.ProductScratchLength];
            sliceSha = Sha256.NewScratch();
            sliceHash = new byte[32];
            int capacity = queueCapacity < 1 ? 1 : queueCapacity;
            queueData = new string[capacity];
            queueSignature = new string[capacity];
            queueCaller = new UdonSharpBehaviour[capacity];
            queueEvent = new string[capacity];
            queueId = new int[capacity];
            keyValid = Secp256k1.LoadPublicKey(publicKeyHex, key, 0, curveScratch, product);
            if (!keyValid)
            {
                Debug.LogError("[SignatureVerifier] invalid public key on " + gameObject.name
                    + " (expected 04 || x || y as 130 hex characters, a point on secp256k1); every verification will fail");
            }
        }
    }
}
