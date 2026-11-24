using System;
using System.Collections.Generic;
using CsS7CommPlus.V3.Protocol;
using CsS7CommPlus.V3.Session;
using CsS7CommPlus.V3.Symbols;

namespace CsS7CommPlus.V3
{
    /// <summary>One item of a batched symbolic read.</summary>
    public class SymbolicReadItem
    {
        /// <summary>The access area: a DB area id, or a process-area RID.</summary>
        public uint AccessArea { get; set; }
        /// <summary>The LID path through the symbol tree.</summary>
        public IReadOnlyList<uint> Lids { get; set; } = new uint[0];
        /// <summary>The symbol's layout CRC; 0 skips the PLC's layout check.</summary>
        public uint SymbolCrc { get; set; }
    }

    /// <summary>
    /// The protocol-version-3 client: browses the PLC's symbols and reads, writes
    /// and subscribes to them by symbolic address.
    ///
    /// Symbolic access is what makes optimized data blocks readable.  With
    /// "Optimized block access" on, the PLC relocates variables between
    /// downloads, so byte offsets are not stable; a symbolic request names the
    /// access area and a LID path, and the PLC walks its own symbol tree.
    ///
    /// Reads are issued with SymbolCRC 0, which skips the PLC's layout check.
    /// The catalog CRC does not match every firmware, and a non-zero value is
    /// rejected with error 0x..9A0013.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (client.py).
    /// </summary>
    public class S7CommPlusClient : IDisposable
    {
        private readonly S7CommPlusConnection _connection;
        private SymbolCatalog? _catalog;
        private byte _subscriptionChangeCounter = 1;
        private uint _subscriptionRelationId = SubscriptionCodec.DefaultRelationId;

        /// <summary>Create a client for the given PLC.</summary>
        public S7CommPlusClient(string host, int port = 102)
        {
            _connection = new S7CommPlusConnection(host, port);
        }

        /// <summary>The underlying session.</summary>
        public S7CommPlusConnection Connection => _connection;

        /// <summary>PLC IP address or host name.</summary>
        public string Host => _connection.Host;

        /// <summary>Whether the session is open.</summary>
        public bool Connected => _connection.Connected;

        /// <summary>Socket and request timeout in milliseconds.</summary>
        public int TimeoutMs
        {
            get => _connection.TimeoutMs;
            set => _connection.TimeoutMs = value;
        }

        /// <summary>
        /// Which session authentication to use.  The default decides from the
        /// PLC's own reply, which is what a driver facing a mixed site wants.
        /// </summary>
        public SessionMode Mode
        {
            get => _connection.Mode;
            set => _connection.Mode = value;
        }

        /// <summary>Raised for each protocol-level diagnostic; wire to the host's logger.</summary>
        public event Action<string>? OnDiagnostic
        {
            add { _connection.OnDiagnostic += value; }
            remove { _connection.OnDiagnostic -= value; }
        }

        /// <summary>Open the session.</summary>
        public void Connect() => _connection.Connect();

        /// <summary>Close the session cleanly.</summary>
        public void Disconnect()
        {
            _catalog = null;
            _connection.Disconnect();
        }

        /// <summary>Close the socket immediately, without the clean-up requests.</summary>
        public void Abort()
        {
            _catalog = null;
            _connection.Abort();
        }

        /// <inheritdoc/>
        public void Dispose() => Disconnect();

        // --- symbolic read / write -----------------------------------------

        /// <summary>
        /// Read one symbol by access area and LID path, returning its raw
        /// big-endian value bytes.
        /// </summary>
        public byte[] ReadSymbolic(uint accessArea, IReadOnlyList<uint> lids, uint symbolCrc = 0)
        {
            var results = ReadSymbolicMulti(new[]
            {
                new SymbolicReadItem { AccessArea = accessArea, Lids = lids, SymbolCrc = symbolCrc },
            });
            if (results.Count == 0 || results[0] == null)
                throw new S7ProtocolException("Symbolic read failed");
            return results[0]!;
        }

        /// <summary>
        /// Read several symbols in one request.  Returns one entry per requested
        /// item in request order, null where the PLC reported an error.
        /// </summary>
        public IList<byte[]?> ReadSymbolicMulti(IReadOnlyList<SymbolicReadItem> items)
        {
            if (items.Count == 0) return new List<byte[]?>();

            var payload = BuildMultiSymbolicReadPayload(items, _connection.ProtocolVersion);
            var response = _connection.SendRequest(FunctionCode.GetMultiVariables, payload, 4);
            var results = ParseReadResponse(response, items.Count);

            if (results.Count != items.Count)
                throw new S7ProtocolException(
                    $"Symbolic multi-read failed: the PLC answered {results.Count} of {items.Count} items");
            return results;
        }

        /// <summary>Write one symbol by access area and LID path.</summary>
        public void WriteSymbolic(uint accessArea, IReadOnlyList<uint> lids, byte[] data,
                                  uint symbolCrc = 0, DataType datatype = DataType.Blob)
        {
            var payload = BuildSymbolicWritePayload(accessArea, lids, data, symbolCrc,
                                                    _connection.ProtocolVersion, datatype);
            var response = _connection.SendRequest(FunctionCode.SetMultiVariables, payload, 4);
            var errors = ParseWriteResponseErrors(response);
            if (errors.Count > 0)
            {
                var parts = new List<string>();
                foreach (var kv in errors) parts.Add($"item {kv.Key}: error {kv.Value}");
                throw new S7ProtocolException("Write failed: " + string.Join(", ", parts));
            }
        }

        private static byte[] BuildMultiSymbolicReadPayload(IReadOnlyList<SymbolicReadItem> items,
                                                            ProtocolVersion protocolVersion)
        {
            var addresses = new List<byte[]>(items.Count);
            int totalFieldCount = 0;

            foreach (var item in items)
            {
                uint subArea = item.AccessArea >= Ids.DbAccessAreaBase
                    ? Ids.DbValueActual
                    : Ids.ControllerAreaValueActual;
                var addr = S7Codec.EncodeItemAddress(item.AccessArea, subArea, item.Lids,
                                                     out int fieldCount, item.SymbolCrc);
                addresses.Add(addr);
                totalFieldCount += fieldCount;
            }

            var p = new List<byte>();
            S7Codec.AppendUInt32(p, 0);                       // InObjectId: none for symbolic access
            Vlq.AppendUInt32(p, (uint)items.Count);           // ItemCount
            Vlq.AppendUInt32(p, (uint)totalFieldCount);       // AddressCount
            foreach (var addr in addresses) p.AddRange(addr);
            p.AddRange(S7Codec.EncodeObjectQualifier(0, protocolVersion));
            S7Codec.AppendUInt32(p, 0);                       // fill; the IntegrityId goes before it
            return p.ToArray();
        }

        private static byte[] BuildSymbolicWritePayload(uint accessArea, IReadOnlyList<uint> lids, byte[] data,
                                                        uint symbolCrc, ProtocolVersion protocolVersion,
                                                        DataType datatype)
        {
            uint subArea = accessArea >= Ids.DbAccessAreaBase ? Ids.DbValueActual : Ids.ControllerAreaValueActual;
            var address = S7Codec.EncodeItemAddress(accessArea, subArea, lids, out int fieldCount, symbolCrc);

            var p = new List<byte>();
            S7Codec.AppendUInt32(p, 0);
            Vlq.AppendUInt32(p, 1);                           // ItemCount
            Vlq.AppendUInt32(p, (uint)fieldCount);            // AddressCount
            p.AddRange(address);
            Vlq.AppendUInt32(p, 1);                           // ItemNumber
            p.AddRange(S7Codec.EncodePValueTyped(datatype, data));
            p.Add(0x00);
            p.AddRange(S7Codec.EncodeObjectQualifier(0, protocolVersion));
            S7Codec.AppendUInt32(p, 0);
            return p.ToArray();
        }

        /// <summary>
        /// The suffix an S7-1200 appends when answering a single-byte scalar read:
        /// the value, then a zero byte and this fixed tail.
        /// </summary>
        private static readonly byte[] ScalarResponseSuffix = { 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 };

        /// <summary>
        /// Parse a GetMultiVariables response into one raw value per item, with
        /// null where the PLC reported an error for that item.
        /// </summary>
        private static List<byte[]?> ParseReadResponse(byte[] response, int expectedCount)
        {
            if (EndsWith(response, ScalarResponseSuffix))
            {
                int bodyLength = response.Length - ScalarResponseSuffix.Length;
                if (bodyLength == 2 && response[1] == 0x00)
                    return new List<byte[]?> { S7Codec.Slice(response, 0, 1) };
            }

            ulong returnValue = Vlq.DecodeUInt64(response, 0, out int offset);
            if (returnValue != 0)
                throw new S7ProtocolException($"Read failed: the PLC returned 0x{returnValue:X}");

            var values = new Dictionary<uint, byte[]>();
            while (offset < response.Length)
            {
                uint itemNr = Vlq.DecodeUInt32(response, offset, out int c);
                offset += c;
                if (itemNr == 0) break;

                var raw = S7Codec.DecodePValueToBytes(response, offset, out int cv);
                offset += cv;

                if (itemNr > expectedCount || values.ContainsKey(itemNr))
                    throw new S7ProtocolException($"Read failed: unexpected or duplicate item {itemNr}");
                values[itemNr] = raw;
            }

            var errors = new Dictionary<uint, ulong>();
            while (offset < response.Length)
            {
                uint itemNr = Vlq.DecodeUInt32(response, offset, out int c);
                offset += c;
                if (itemNr == 0) break;

                ulong errValue = Vlq.DecodeUInt64(response, offset, out int ce);
                offset += ce;

                if (itemNr > expectedCount || values.ContainsKey(itemNr) || errors.ContainsKey(itemNr))
                    throw new S7ProtocolException($"Read failed: unexpected or duplicate item {itemNr}");
                errors[itemNr] = errValue;
            }

            if (values.Count + errors.Count != expectedCount)
                throw new S7ProtocolException(
                    $"Read failed: the PLC answered {values.Count + errors.Count} of {expectedCount} items");

            var results = new List<byte[]?>(expectedCount);
            for (uint i = 1; i <= expectedCount; i++)
                results.Add(values.TryGetValue(i, out var v) ? v : null);
            return results;
        }

        private static Dictionary<uint, ulong> ParseWriteResponseErrors(byte[] response)
        {
            ulong returnValue = Vlq.DecodeUInt64(response, 0, out int offset);
            if (returnValue != 0)
                throw new S7ProtocolException($"Write failed with return value 0x{returnValue:X}");

            var errors = new Dictionary<uint, ulong>();
            while (offset < response.Length)
            {
                uint itemNr = Vlq.DecodeUInt32(response, offset, out int c);
                offset += c;
                if (itemNr == 0) break;

                ulong errValue = Vlq.DecodeUInt64(response, offset, out int ce);
                offset += ce;
                errors[itemNr] = errValue;
            }
            return errors;
        }

        private static bool EndsWith(byte[] data, byte[] suffix)
        {
            if (data.Length < suffix.Length) return false;
            for (int i = 0; i < suffix.Length; i++)
            {
                if (data[data.Length - suffix.Length + i] != suffix[i]) return false;
            }
            return true;
        }

        // --- browse ---------------------------------------------------------

        /// <summary>The cached symbol catalog, browsing the PLC on first use.</summary>
        public SymbolCatalog TagCatalog => _catalog ?? RefreshTagCatalog();

        /// <summary>
        /// The names the browse roots the process areas under.  A data block's
        /// subtree is rooted at the block's own name, but the I, Q and M areas have
        /// none, so the browse invents one; TIA Portal shows those symbols as plain
        /// PLC tags, so the invented prefix is dropped from the catalogued name and
        /// kept only as an alternative spelling.
        /// </summary>
        private static readonly string[] ProcessAreaRoots =
            { "IArea.", "QArea.", "MArea.", "S7Timers.", "S7Counters." };

        /// <summary>Browse the PLC and replace the cached symbol catalog.</summary>
        public SymbolCatalog RefreshTagCatalog()
        {
            var tags = new List<SymbolicTag>();
            var aliases = new List<KeyValuePair<string, SymbolicTag>>();

            foreach (var info in Browse())
            {
                var tag = SymbolicTag.FromVarInfo(info);
                string plain = StripProcessAreaRoot(tag.Name);
                if (!string.Equals(plain, tag.Name, StringComparison.Ordinal))
                {
                    aliases.Add(new KeyValuePair<string, SymbolicTag>(tag.Name, tag));
                    tag.Name = plain;
                }
                tags.Add(tag);
            }

            _catalog = new SymbolCatalog(tags, aliases);
            return _catalog;
        }

        private static string StripProcessAreaRoot(string name)
        {
            foreach (var root in ProcessAreaRoots)
            {
                if (name.StartsWith(root, StringComparison.Ordinal) && name.Length > root.Length)
                    return name.Substring(root.Length);
            }
            return name;
        }

        /// <summary>Discard the cached catalog after a PLC program change.</summary>
        public void InvalidateTagCatalog() => _catalog = null;

        /// <summary>Resolve a symbolic name against the catalog, browsing if needed.</summary>
        public SymbolicTag ResolveTag(string name) => TagCatalog.Resolve(name);

        /// <summary>
        /// Browse the full symbol tree and return it as a flat list of readable
        /// tags.  The steps are: enumerate the data blocks, resolve each block's
        /// type-info relation id, explore the type-info container, then recombine
        /// the two into the symbol tree.
        /// </summary>
        public List<VarInfo> Browse()
        {
            var rootNodes = new List<SymbolNode>();

            foreach (var db in ListDataBlocks())
            {
                if (db.Number <= 0 || db.Rid == 0) continue;

                uint tiRid = ReadTypeInfoRid(db.Rid);
                if (tiRid == 0) continue;            // a load-memory-only block, with no readable value

                rootNodes.Add(new SymbolNode
                {
                    NodeType = NodeType.Root,
                    Name = db.Name,
                    AccessId = db.Rid,
                    RelationId = tiRid,
                });
            }

            // The native process areas, with their fixed synthetic type-info ids.
            AddAreaRoot(rootNodes, "IArea", Ids.NativeTheIAreaRid, 0x90010000);
            AddAreaRoot(rootNodes, "QArea", Ids.NativeTheQAreaRid, 0x90020000);
            AddAreaRoot(rootNodes, "MArea", Ids.NativeTheMAreaRid, 0x90030000);
            AddAreaRoot(rootNodes, "S7Timers", Ids.NativeTheS7TimersRid, 0x90050000);
            AddAreaRoot(rootNodes, "S7Counters", Ids.NativeTheS7CountersRid, 0x90060000);

            var typeObjects = ExploreTypeInfoContainer();

            SymbolTree.BuildTree(rootNodes, typeObjects);
            return SymbolTree.BuildFlatList(rootNodes);
        }

        private static void AddAreaRoot(List<SymbolNode> nodes, string name, uint accessRid, uint tiRid) =>
            nodes.Add(new SymbolNode
            {
                NodeType = NodeType.Root,
                Name = name,
                AccessId = accessRid,
                RelationId = tiRid,
            });

        /// <summary>A data block advertised by the PLC.</summary>
        public class DataBlockInfo
        {
            /// <summary>The block's symbolic name.</summary>
            public string Name { get; set; } = string.Empty;
            /// <summary>The block number, as in DB7.</summary>
            public int Number { get; set; }
            /// <summary>The block's relation id, which is also its access area.</summary>
            public uint Rid { get; set; }
        }

        /// <summary>
        /// List the PLC's data blocks.  A TLS session explores the PLC program
        /// object and asks for the name and number attributes; a session-key CPU
        /// wants the data-block wildcard address in the fixed layout TIA Portal
        /// sends, which the VLQ form does not match.
        /// </summary>
        public List<DataBlockInfo> ListDataBlocks()
        {
            var payload = _connection.SessionKeyActive
                ? BuildExploreWildcardRequest(DataBlockWildcardAddress)
                : BuildExploreRequest(Ids.NativeThePlcProgramRid,
                                      new[] { Ids.ObjectVariableTypeName, Ids.BlockBlockNumber });

            var response = _connection.SendRequest(FunctionCode.Explore, payload, 5);
            return ParseExploreDataBlocks(response);
        }

        /// <summary>The address that matches every data block in an Explore request.</summary>
        private const uint DataBlockWildcardAddress = 0x8A11FFFF;

        /// <summary>
        /// Build the Explore request a V1-initial CPU expects: a fixed-width
        /// 32-bit object id followed by fixed parameters, rather than the VLQ form.
        /// </summary>
        internal static byte[] BuildExploreWildcardRequest(uint exploreId, byte sequence = 10)
        {
            var p = new List<byte>();
            S7Codec.AppendUInt32(p, exploreId);
            p.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01, 0x00, 0x00 });
            p.Add(sequence);
            p.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 });
            return p.ToArray();
        }

        /// <summary>
        /// Read LID 1 of a block to get its type-info relation id, which an
        /// instance DB does not share with its own RID.  Returns 0 when the block
        /// has no readable value.
        /// </summary>
        private uint ReadTypeInfoRid(uint dbRid)
        {
            byte[] raw;
            try
            {
                raw = ReadSymbolic(dbRid, new uint[] { 1 });
            }
            catch (S7ConnectionException) { throw; }       // a lost connection must reach the caller
            catch (S7TimeoutException) { throw; }
            catch (S7Exception) { return 0; }              // an unreadable block, not a transport failure

            return raw.Length >= 4 ? S7Codec.ReadUInt32(raw, 0) : 0;
        }

        /// <summary>Explore the OMS type-info container and return its per-type objects.</summary>
        private List<TypeInfo.PObject> ExploreTypeInfoContainer()
        {
            var payload = BuildExploreRequest(Ids.ObjectOmsTypeInfoContainer, new uint[0]);
            var response = _connection.SendRequest(FunctionCode.Explore, payload, 5);
            return TypeInfo.ExtractTypeInfoObjects(response);
        }

        /// <summary>
        /// Build a structured Explore request for one object.  The trailing
        /// 32-bit fill plus filler byte are what the IntegrityId is spliced in
        /// before, hence an integrity tail of 5 for Explore.
        /// </summary>
        internal static byte[] BuildExploreRequest(uint exploreId, IReadOnlyList<uint> attributeIds)
        {
            var p = new List<byte>();
            S7Codec.AppendUInt32(p, exploreId);        // ExploreId, a fixed UInt32 rather than a VLQ
            Vlq.AppendUInt32(p, 0);                    // ExploreRequestId: none
            p.Add(1);                                  // ExploreChildsRecursive
            p.Add(1);                                  // the protocol always carries 1 here
            p.Add(0);                                  // ExploreParents
            p.Add(0);                                  // no filter objects follow
            Vlq.AppendUInt32(p, (uint)attributeIds.Count);
            foreach (var id in attributeIds) Vlq.AppendUInt32(p, id);
            S7Codec.AppendUInt32(p, 0);
            p.Add(0);
            return p.ToArray();
        }

        /// <summary>
        /// Parse an Explore of the PLC program into its data blocks.  The object
        /// tree is walked with a stack of relation id, class id and name; a data
        /// block is an object whose class id is the DB class and whose relation id
        /// is a DB area id, so its number is the low 16 bits of that id.
        /// </summary>
        /// <summary>One open object while the Explore tree is being walked.</summary>
        private class ExploreFrame
        {
            public uint RelationId;
            public uint ClassId;
            public string Name = string.Empty;
        }

        private static List<DataBlockInfo> ParseExploreDataBlocks(byte[] response)
        {
            var datablocks = new List<DataBlockInfo>();
            int offset = 0;

            if (offset < response.Length)
            {
                Vlq.DecodeUInt64(response, offset, out int c);
                offset += c;
            }

            var stack = new List<ExploreFrame>();

            while (offset < response.Length)
            {
                byte tag = response[offset];

                if (tag == (byte)ElementId.StartOfObject)
                {
                    offset += 1;
                    if (offset + 4 > response.Length) break;
                    uint relid = S7Codec.ReadUInt32(response, offset);
                    offset += 4;
                    uint classId = Vlq.DecodeUInt32(response, offset, out int cc);
                    offset += cc;
                    Vlq.DecodeUInt32(response, offset, out int cf);      // ClassFlags
                    offset += cf;
                    Vlq.DecodeUInt32(response, offset, out int ca);      // AttributeId
                    offset += ca;

                    stack.Add(new ExploreFrame { RelationId = relid, ClassId = classId });
                }
                else if (tag == (byte)ElementId.TerminatingObject)
                {
                    offset += 1;
                    if (stack.Count > 0)
                    {
                        var top = stack[stack.Count - 1];
                        stack.RemoveAt(stack.Count - 1);
                        if (top.ClassId == Ids.DbClassRid && (top.RelationId >> 16) == 0x8A0E)
                        {
                            datablocks.Add(new DataBlockInfo
                            {
                                Name = top.Name,
                                Number = (int)(top.RelationId & 0xFFFF),
                                Rid = top.RelationId,
                            });
                        }
                    }
                }
                else if (tag == (byte)ElementId.Attribute)
                {
                    offset += 1;
                    uint attrId = Vlq.DecodeUInt32(response, offset, out int c);
                    offset += c;

                    byte[] value;
                    try
                    {
                        value = S7Codec.DecodePValueToBytes(response, offset, out int cv);
                        offset += cv;
                    }
                    catch (S7ProtocolException)
                    {
                        break;
                    }

                    if (attrId == Ids.ObjectVariableTypeName && stack.Count > 0)
                        stack[stack.Count - 1].Name = DecodeBlockName(value);
                }
                else
                {
                    offset += 1;        // response preamble, or an element tag we do not handle
                }
            }

            return datablocks;
        }

        /// <summary>
        /// Decode a block name.  It arrives as a WString, but an S7-1500 sends the
        /// ASCII range one byte per character while other firmware sends genuine
        /// UTF-16BE, where an ASCII character carries a zero high byte.  A symbol
        /// name never contains an embedded null, so the presence of one tells the
        /// two encodings apart unambiguously.
        /// </summary>
        private static string DecodeBlockName(byte[] value)
        {
            bool hasNull = Array.IndexOf(value, (byte)0x00) >= 0;
            string text = hasNull
                ? System.Text.Encoding.BigEndianUnicode.GetString(value)
                : System.Text.Encoding.GetEncoding("ISO-8859-1").GetString(value);
            return text.TrimEnd('\0');
        }

        // --- CPU state ------------------------------------------------------

        /// <summary>
        /// The CPU's operating state: "RUN", "STOP" or "UNKNOWN".  The two
        /// execution-state attributes move together across transitions, so both
        /// must agree before a state is reported; that keeps an absent or
        /// default-initialized attribute from reading as STOP.
        /// </summary>
        public string GetCpuState()
        {
            var payload = BuildExploreRequest(Ids.NativeTheCpuExecUnitRid, new uint[0]);
            var response = _connection.SendRequest(FunctionCode.Explore, payload, 5);
            return ParseCpuState(response);
        }

        private static string ParseCpuState(byte[] response)
        {
            var executing = new HashSet<ushort>();
            var operatingMode = new HashSet<ushort>();

            int offset = 0;
            while (offset < response.Length)
            {
                int found = Array.IndexOf(response, (byte)ElementId.Attribute, offset);
                if (found < 0) break;
                offset = found + 1;

                uint attributeId;
                int consumed;
                try { attributeId = Vlq.DecodeUInt32(response, offset, out consumed); }
                catch (S7ProtocolException) { continue; }

                int valueOffset = offset + consumed;
                if (attributeId != Ids.CpuExecUnitExecuting && attributeId != Ids.CpuExecUnitOperatingMode) continue;

                // Both attributes are scalar 16-bit values.  Checking the exact PValue
                // header also makes a chance byte match inside opaque data inert.
                if (valueOffset + 4 > response.Length ||
                    response[valueOffset] != 0x00 || response[valueOffset + 1] != (byte)DataType.UInt)
                    continue;

                ushort value = S7Codec.ReadUInt16(response, valueOffset + 2);
                if (attributeId == Ids.CpuExecUnitExecuting) executing.Add(value);
                else operatingMode.Add(value);
            }

            if (executing.Count == 1 && executing.Contains(1) &&
                operatingMode.Count == 1 && operatingMode.Contains(7)) return "RUN";
            if (executing.Count == 1 && executing.Contains(0) &&
                operatingMode.Count == 1 && operatingMode.Contains(0)) return "STOP";
            return "UNKNOWN";
        }

        // --- subscriptions ---------------------------------------------------

        /// <summary>
        /// Create a data-change subscription.  The PLC then pushes an initial
        /// value for every item and the changes after it, and sends an empty
        /// notification each cycle when nothing changed.
        /// </summary>
        /// <param name="items">The symbols to watch.</param>
        /// <param name="cycleMs">Sampling cycle in milliseconds.</param>
        /// <param name="creditLimit">
        /// How many notifications the PLC may send before it waits to be given
        /// more credit. The default of -1 asks for no limit, so the CPU keeps
        /// sending; a positive value is honored to its low byte only, and the
        /// subscription then falls silent. See
        /// <see cref="SubscriptionCodec.DefaultCreditLimit"/>.
        /// </param>
        /// <returns>The subscription id the PLC assigned.</returns>
        public uint CreateSubscription(IReadOnlyList<SubscriptionItem> items, int cycleMs = 100,
                                      short creditLimit = SubscriptionCodec.DefaultCreditLimit)
        {
            if (_connection.SubscriptionContainerId == 0)
                throw new S7ProtocolException("The PLC did not provide a subscription container object");

            var payload = SubscriptionCodec.BuildSubscriptionRequest(
                _connection.SubscriptionContainerId, items, out int integrityTail,
                cycleMs, creditLimit, _subscriptionChangeCounter, _subscriptionRelationId);

            var response = _connection.SendRequest(FunctionCode.CreateObject, payload, integrityTail);
            var objectIds = S7Codec.ParseCreateObjectSessionId(response, out _, out ulong returnValue);

            if (returnValue != 0 || objectIds.Count == 0)
                throw new S7ProtocolException($"Subscription creation failed: the PLC returned 0x{returnValue:X}");

            _subscriptionChangeCounter = (byte)(_subscriptionChangeCounter % 0xFF + 1);
            _subscriptionRelationId = unchecked(_subscriptionRelationId + 1);
            return objectIds[0];
        }

        /// <summary>Whether a notification is already queued from earlier traffic.</summary>
        public bool HasQueuedNotification => _connection.HasQueuedNotification;

        /// <summary>Block until the PLC sends one data-change notification.</summary>
        public SubscriptionNotification ReceiveSubscriptionNotification() =>
            SubscriptionCodec.ParseNotification(_connection.ReceiveNotification());

        /// <summary>Set how long a wait for a notification may block.</summary>
        public void SetNotificationTimeout(int milliseconds) => _connection.SetReceiveTimeout(milliseconds);

        /// <summary>
        /// Delete a data-change subscription.  The subscription's children belong
        /// to the session's subscription container, and it is that container the
        /// PLC expects to be deleted rather than the child id.
        /// </summary>
        public void DeleteSubscription(uint subscriptionId)
        {
            if (_connection.SubscriptionContainerId == 0)
                throw new S7ProtocolException("The PLC did not provide a subscription container object");

            var payload = SubscriptionCodec.BuildDeleteSubscriptionRequest(
                _connection.SubscriptionContainerId, _connection.ProtocolVersion);
            _connection.SendRequest(FunctionCode.DeleteObject, payload, 4);
        }
    }
}
