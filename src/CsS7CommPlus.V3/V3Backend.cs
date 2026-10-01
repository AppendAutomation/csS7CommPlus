using System;
using System.Collections.Generic;
using System.Linq;
using CsS7CommPlus.Backend;
using CsS7CommPlus.V3.Protocol;
using CsS7CommPlus.V3.Session;
using CsS7CommPlus.V3.Symbols;
using CsS7CommPlus.V3.Values;

namespace CsS7CommPlus.V3
{
    /// <summary>
    /// The protocol-version-3 backend for <see cref="CsS7CommPlus.PLC"/>: it
    /// fills in the Explore, symbolic read/write and subscription operations the
    /// clear-text V1 path cannot perform.
    ///
    /// Wire it up with
    /// <c>plc.V3BackendFactory = p =&gt; new V3Backend(p);</c>
    /// and <c>GetTagList</c>, <c>Read</c>, <c>ReadList</c> and <c>Write</c> then
    /// work against a live PLC.
    ///
    /// Symbols are resolved once per session from the PLC's own symbol tree, so
    /// the first call browses and later calls are served from that catalog.  It
    /// is invalidated by <see cref="Close"/>, and a PLC program change therefore
    /// needs a reconnect — which is also what the PLC's own layout change
    /// requires.
    /// </summary>
    public class V3Backend : IV3Backend, IV3SubscriptionBackend, IV3AbortableBackend, IV3SymbolResolver, IDisposable
    {
        private readonly S7CommPlusClient _client;
        private readonly Dictionary<uint, string> _subscribedByReference = new Dictionary<uint, string>();
        private readonly Dictionary<string, SymbolicTag> _subscribedTags = new Dictionary<string, SymbolicTag>(StringComparer.Ordinal);

        private List<V3TagInfo>? _tags;
        private uint _subscriptionId;

        /// <summary>Create a backend for the given PLC facade.</summary>
        public V3Backend(PLC plc)
        {
            if (plc == null) throw new ArgumentNullException(nameof(plc));
            _client = new S7CommPlusClient(plc.IPAddress, plc.Port)
            {
                TimeoutMs = (int)(plc.SocketTimeout * 1000),
            };
        }

        /// <summary>Create a backend directly against a host, for use without the facade.</summary>
        public V3Backend(string host, int port = 102, int timeoutMs = 5000)
        {
            _client = new S7CommPlusClient(host, port) { TimeoutMs = timeoutMs };
        }

        /// <summary>The underlying V3 client, for operations outside the seam.</summary>
        public S7CommPlusClient Client => _client;

        /// <summary>Raised for each protocol-level diagnostic; wire to the host's logger.</summary>
        public event Action<string>? OnDiagnostic
        {
            add { _client.OnDiagnostic += value; }
            remove { _client.OnDiagnostic -= value; }
        }

        /// <inheritdoc/>
        public bool Connected => _client.Connected;

        /// <inheritdoc/>
        public void Connect() => _client.Connect();

        /// <inheritdoc/>
        public void Close()
        {
            if (Subscribed)
            {
                try { Unsubscribe(); } catch { /* best effort */ }
            }
            _tags = null;
            _client.Disconnect();
        }

        /// <inheritdoc/>
        public void Abort()
        {
            _tags = null;
            _subscriptionId = 0;
            _subscribedByReference.Clear();
            _subscribedTags.Clear();
            _client.Abort();
        }

        /// <inheritdoc/>
        public void Dispose() => Close();

        // --- browse ---------------------------------------------------------

        /// <inheritdoc/>
        public IList<V3TagInfo> Tags(bool refresh = false)
        {
            if (_tags != null && !refresh) return _tags;

            var catalog = refresh ? _client.RefreshTagCatalog() : _client.TagCatalog;
            var list = new List<V3TagInfo>(catalog.Count);
            foreach (var tag in catalog)
            {
                list.Add(new V3TagInfo
                {
                    Name = tag.Name,
                    DataType = tag.SoftDataType.ToString().ToUpperInvariant(),
                    AccessArea = tag.AccessArea,
                    Lids = tag.Lids.Select(l => unchecked((int)l)).ToList(),
                });
            }
            _tags = list;
            return _tags;
        }

        /// <inheritdoc/>
        public IList<string> Unresolved(IEnumerable<string> names)
        {
            var catalog = _client.TagCatalog;
            var missing = new List<string>();
            foreach (var name in names)
            {
                if (!catalog.TryResolve(name, out _)) missing.Add(name);
            }
            return missing;
        }

        /// <inheritdoc/>
        public string CpuState()
        {
            try { return _client.GetCpuState(); }
            catch (S7Exception) { return "UNKNOWN"; }
        }

        // --- read / write ----------------------------------------------------

        /// <inheritdoc/>
        public V3ReadResult Read(string name)
        {
            var results = ReadMany(new[] { name }, 1);
            return results.Count > 0
                ? results[0]
                : new V3ReadResult { Name = name, Ok = false, Error = "no result" };
        }

        /// <inheritdoc/>
        public IList<V3ReadResult> ReadMany(IEnumerable<string> names, int chunk = 40)
        {
            var list = names.ToList();
            var results = new List<V3ReadResult>(list.Count);
            if (list.Count == 0) return results;
            if (chunk < 1) chunk = 1;

            SymbolCatalog catalog;
            try
            {
                catalog = _client.TagCatalog;
            }
            catch (Exception e)
            {
                foreach (var name in list)
                    results.Add(new V3ReadResult { Name = name, Ok = false, Error = e.Message });
                return results;
            }

            // Resolve first so an unknown name costs nothing on the wire.
            var resolved = new List<SymbolicTag?>(list.Count);
            foreach (var name in list)
                resolved.Add(catalog.TryResolve(name, out var tag) ? tag : null);

            for (int start = 0; start < list.Count; start += chunk)
            {
                int count = Math.Min(chunk, list.Count - start);
                ReadBatch(list, resolved, start, count, results);
            }

            return results;
        }

        /// <summary>
        /// Read one batch.  If the batch itself fails — an unusual tag, or a
        /// response the PLC considers over-large — it is retried one tag at a
        /// time so a single bad tag never costs the rest of the batch.
        /// </summary>
        private void ReadBatch(List<string> names, List<SymbolicTag?> resolved,
                               int start, int count, List<V3ReadResult> results)
        {
            var items = new List<SymbolicReadItem>(count);
            var itemTags = new List<SymbolicTag>(count);

            for (int i = start; i < start + count; i++)
            {
                var tag = resolved[i];
                if (tag == null) continue;
                items.Add(new SymbolicReadItem
                {
                    AccessArea = tag.AccessArea,
                    Lids = tag.Lids,
                    SymbolCrc = 0,                  // skip the PLC's layout check
                });
                itemTags.Add(tag);
            }

            IList<byte[]?>? raws = null;
            if (items.Count > 0)
            {
                try { raws = _client.ReadSymbolicMulti(items); }
                catch (S7ConnectionException) { throw; }
                catch (S7TimeoutException) { throw; }
                catch (S7Exception) { raws = null; }    // fall back to one tag at a time
            }

            if (raws == null)
            {
                for (int i = start; i < start + count; i++)
                    results.Add(ReadOne(names[i], resolved[i]));
                return;
            }

            int resultIndex = 0;
            for (int i = start; i < start + count; i++)
            {
                var tag = resolved[i];
                if (tag == null)
                {
                    results.Add(new V3ReadResult { Name = names[i], Ok = false, Error = "tag not found" });
                    continue;
                }

                var raw = raws[resultIndex++];
                results.Add(raw == null
                    ? new V3ReadResult { Name = names[i], Ok = false, Error = "read failed" }
                    : new V3ReadResult
                    {
                        Name = names[i],
                        Value = S7ValueDecoder.Decode(tag.SoftDataType, raw),
                        Ok = true,
                    });
            }
        }

        private V3ReadResult ReadOne(string name, SymbolicTag? tag)
        {
            if (tag == null) return new V3ReadResult { Name = name, Ok = false, Error = "tag not found" };
            try
            {
                var raw = _client.ReadSymbolic(tag.AccessArea, tag.Lids);
                return new V3ReadResult
                {
                    Name = name,
                    Value = S7ValueDecoder.Decode(tag.SoftDataType, raw),
                    Ok = true,
                };
            }
            catch (S7ConnectionException) { throw; }
            catch (S7TimeoutException) { throw; }
            catch (Exception e)
            {
                return new V3ReadResult { Name = name, Ok = false, Error = e.Message };
            }
        }

        /// <inheritdoc/>
        public V3ReadResult Write(string name, object value, string? datatypeOverride = null)
        {
            SymbolicTag tag;
            try { tag = _client.ResolveTag(name); }
            catch (KeyNotFoundException) { return new V3ReadResult { Name = name, Ok = false, Error = "tag not found" }; }
            catch (Exception e) { return new V3ReadResult { Name = name, Ok = false, Error = e.Message }; }

            var softType = tag.SoftDataType;
            if (!string.IsNullOrEmpty(datatypeOverride) &&
                Enum.TryParse<SoftDataType>(datatypeOverride, true, out var overridden))
                softType = overridden;

            if (!SymbolicTag.WireTypes.TryGetValue(softType, out var wireType))
                return new V3ReadResult { Name = name, Ok = false, Error = $"no wire type for {softType}" };

            try
            {
                var raw = S7ValueDecoder.Encode(softType, value);
                _client.WriteSymbolic(tag.AccessArea, tag.Lids, raw, 0, wireType);
                return new V3ReadResult
                {
                    Name = name,
                    Value = S7ValueDecoder.Decode(softType, raw),
                    Ok = true,
                };
            }
            catch (S7ConnectionException) { throw; }
            catch (S7TimeoutException) { throw; }
            catch (Exception e)
            {
                return new V3ReadResult { Name = name, Ok = false, Error = e.Message };
            }
        }

        // --- subscriptions ----------------------------------------------------

        /// <inheritdoc/>
        public bool Subscribed => _subscriptionId != 0;

        /// <inheritdoc/>
        public bool Subscribe(IEnumerable<string> names, int cycleMs)
        {
            if (Subscribed) Unsubscribe();

            var catalog = _client.TagCatalog;
            var items = new List<SubscriptionItem>();
            uint reference = 1;

            _subscribedByReference.Clear();
            _subscribedTags.Clear();

            foreach (var name in names)
            {
                if (!catalog.TryResolve(name, out var tag)) continue;
                items.Add(new SubscriptionItem(tag.AccessArea, tag.Lids, tag.AccessSubArea, 0, reference));
                _subscribedByReference[reference] = name;
                _subscribedTags[name] = tag;
                reference++;
            }

            if (items.Count == 0) return false;

            try
            {
                _subscriptionId = _client.CreateSubscription(items, cycleMs);
                return _subscriptionId != 0;
            }
            catch (S7ConnectionException) { throw; }
            catch (S7TimeoutException) { throw; }
            catch (S7Exception)
            {
                // A PLC that refuses the subscription leaves the caller to poll.
                _subscriptionId = 0;
                _subscribedByReference.Clear();
                _subscribedTags.Clear();
                return false;
            }
        }

        /// <inheritdoc/>
        public IList<V3SubscriptionValue>? WaitForChanges(int timeoutMs)
        {
            if (!Subscribed) return null;

            _client.SetNotificationTimeout(timeoutMs);
            SubscriptionNotification notification;
            try
            {
                notification = _client.ReceiveSubscriptionNotification();
            }
            catch (S7TimeoutException)
            {
                return null;
            }

            var values = new List<V3SubscriptionValue>(notification.Values.Count + notification.Errors.Count);

            foreach (var kv in notification.Values)
            {
                if (!_subscribedByReference.TryGetValue(kv.Key, out var name)) continue;
                var tag = _subscribedTags[name];
                values.Add(new V3SubscriptionValue
                {
                    Name = name,
                    Value = S7ValueDecoder.Decode(tag.SoftDataType, kv.Value),
                    IsGood = true,
                });
            }

            foreach (var kv in notification.Errors)
            {
                if (!_subscribedByReference.TryGetValue(kv.Key, out var name)) continue;
                values.Add(new V3SubscriptionValue { Name = name, Value = null, IsGood = false });
            }

            return values;
        }

        /// <inheritdoc/>
        public void Unsubscribe()
        {
            if (_subscriptionId == 0) return;
            try { _client.DeleteSubscription(_subscriptionId); }
            finally
            {
                _subscriptionId = 0;
                _subscribedByReference.Clear();
                _subscribedTags.Clear();
            }
        }
    }
}
