using System;
using System.Collections.Generic;
using System.Text;
using CsS7CommPlus.V3.Protocol;

namespace CsS7CommPlus.V3.Session
{
    /// <summary>One symbolic variable included in a data subscription.</summary>
    public class SubscriptionItem
    {
        /// <summary>The access area: a DB area id, or a process-area RID.</summary>
        public uint AccessArea { get; }
        /// <summary>The LID path through the symbol tree.</summary>
        public IReadOnlyList<uint> Lids { get; }
        /// <summary>The access sub-area, inferred from the access area when not given.</summary>
        public uint? AccessSubArea { get; }
        /// <summary>The symbol's layout CRC; 0 skips the PLC's layout check.</summary>
        public uint SymbolCrc { get; }
        /// <summary>
        /// A stable id the PLC quotes back in each notification.  Zero means the
        /// item's one-based position in the subscription is used.
        /// </summary>
        public uint ReferenceId { get; }

        /// <summary>Create a subscription item.</summary>
        public SubscriptionItem(uint accessArea, IReadOnlyList<uint> lids,
                                uint? accessSubArea = null, uint symbolCrc = 0, uint referenceId = 0)
        {
            if (lids == null || lids.Count == 0)
                throw new ArgumentException("A subscription item requires at least one LID", nameof(lids));

            AccessArea = accessArea;
            Lids = lids;
            AccessSubArea = accessSubArea;
            SymbolCrc = symbolCrc;
            ReferenceId = referenceId;
        }

        /// <summary>The explicit or inferred access sub-area.</summary>
        public uint ResolvedSubArea
        {
            get
            {
                if (AccessSubArea != null) return AccessSubArea.Value;
                if ((AccessArea & 0xFFFF0000) == Ids.DbAccessAreaBase) return Ids.DbValueActual;
                return Ids.ControllerAreaValueActual;
            }
        }
    }

    /// <summary>The values and errors carried by one subscription notification.</summary>
    public class SubscriptionNotification
    {
        /// <summary>The subscription the notification belongs to.</summary>
        public uint SubscriptionId { get; set; }
        /// <summary>The PLC's credit tick for flow control.</summary>
        public byte CreditTick { get; set; }
        /// <summary>The notification's sequence number.</summary>
        public uint SequenceNumber { get; set; }
        /// <summary>The change counter the subscription was created with.</summary>
        public byte ChangeCounter { get; set; }
        /// <summary>Values by reference id, as raw big-endian bytes.</summary>
        public Dictionary<uint, byte[]> Values { get; } = new Dictionary<uint, byte[]>();
        /// <summary>Per-item error statuses by reference id.</summary>
        public Dictionary<uint, byte> Errors { get; } = new Dictionary<uint, byte>();
        /// <summary>The PLC's timestamp, when the notification carried one.</summary>
        public ulong? Timestamp { get; set; }
    }

    /// <summary>
    /// Encoding of data-change subscription requests and decoding of the
    /// notifications they produce.  Subscriptions address variables by their
    /// symbolic access sequence, since byte offsets do not identify variables in
    /// an optimized data block.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (subscription.py).
    /// </summary>
    public static class SubscriptionCodec
    {
        /// <summary>The relation id the first subscription of a session is created with.</summary>
        public const uint DefaultRelationId = 0x7FFFC001;

        private static void AppendAttribute(List<byte> buffer, uint attributeId, byte[] value)
        {
            buffer.Add((byte)ElementId.Attribute);
            Vlq.AppendUInt32(buffer, attributeId);
            buffer.AddRange(value);
        }

        private static byte[] Scalar(DataType dataType, params byte[] data)
        {
            var o = new List<byte>(data.Length + 2) { 0x00, (byte)dataType };
            o.AddRange(data);
            return o.ToArray();
        }

        private static byte[] ReferenceList(IReadOnlyList<SubscriptionItem> items, byte changeCounter)
        {
            var values = new List<uint>
            {
                0x80000000u | ((uint)(changeCounter & 0xFF) << 16),
                0,
                (uint)items.Count,
            };

            var used = new HashSet<uint>();
            for (int i = 0; i < items.Count; i++)
            {
                var item = items[i];
                uint referenceId = item.ReferenceId != 0 ? item.ReferenceId : (uint)(i + 1);
                if (!used.Add(referenceId))
                    throw new ArgumentException($"Duplicate subscription reference id {referenceId}", nameof(items));

                values.Add(0x80040000u | (uint)(1 + item.Lids.Count));
                values.Add(referenceId);
                values.Add(0);
                values.Add(item.AccessArea);
                values.Add(item.SymbolCrc);
                values.Add(item.ResolvedSubArea);
                foreach (var lid in item.Lids) values.Add(lid);
            }

            var encoded = new List<byte> { 0x20, (byte)DataType.UDInt };
            Vlq.AppendUInt32(encoded, (uint)values.Count);
            foreach (var value in values) Vlq.AppendUInt32(encoded, value);
            return encoded.ToArray();
        }

        /// <summary>
        /// Build the CreateObject payload for a data-change subscription, and the
        /// IntegrityId tail it must be sent with.  CreateObject carries its
        /// IntegrityId between the request set and the object tree, rather than
        /// near the trailing padding most requests use.
        /// </summary>
        public static byte[] BuildSubscriptionRequest(uint subscriptionContainerId,
                                                      IReadOnlyList<SubscriptionItem> items,
                                                      out int integrityTail,
                                                      int cycleMs = 100,
                                                      short creditLimit = DefaultCreditLimit,
                                                      byte changeCounter = 1,
                                                      uint relationId = DefaultRelationId,
                                                      byte routeMode = 0x14)
        {
            if (items == null || items.Count == 0)
                throw new ArgumentException("A subscription requires at least one item", nameof(items));
            if (cycleMs < 0)
                throw new ArgumentOutOfRangeException(nameof(cycleMs), "cycleMs must not be negative");
            if (creditLimit < -1)
                throw new ArgumentOutOfRangeException(nameof(creditLimit),
                    "creditLimit must be -1 (unlimited) or a positive signed 16-bit value");
            if (changeCounter < 1)
                throw new ArgumentOutOfRangeException(nameof(changeCounter), "changeCounter must be between 1 and 255");

            var p = new List<byte>();
            S7Codec.AppendUInt32(p, subscriptionContainerId);
            p.AddRange(Scalar(DataType.UDInt, Vlq.EncodeUInt32(0)));
            S7Codec.AppendUInt32(p, 0);
            int requestSetSize = p.Count;

            p.Add((byte)ElementId.StartOfObject);
            S7Codec.AppendUInt32(p, relationId);
            Vlq.AppendUInt32(p, Ids.ClassSubscription);
            Vlq.AppendUInt32(p, 0);
            Vlq.AppendUInt32(p, 0);

            var name = Encoding.UTF8.GetBytes($"Subscription_{relationId}");
            var nameValue = new List<byte> { 0x00, (byte)DataType.WString };
            Vlq.AppendUInt32(nameValue, (uint)name.Length);
            nameValue.AddRange(name);
            AppendAttribute(p, Ids.ObjectVariableTypeName, nameValue.ToArray());

            AppendAttribute(p, Ids.SubscriptionFunctionClassId, Scalar(DataType.USInt, 0x00));
            AppendAttribute(p, Ids.SubscriptionMissedSendings, Scalar(DataType.UInt, 0x00, 0x00));
            AppendAttribute(p, Ids.SubscriptionSubsystemError, Scalar(DataType.LInt, Vlq.EncodeInt64(0)));
            AppendAttribute(p, Ids.SubscriptionRouteMode, Scalar(DataType.USInt, routeMode));
            AppendAttribute(p, Ids.SubscriptionActive, Scalar(DataType.Bool, 0x01));
            AppendAttribute(p, Ids.SubscriptionReferenceList, ReferenceList(items, changeCounter));
            AppendAttribute(p, Ids.SubscriptionCycleTime, Scalar(DataType.UDInt, Vlq.EncodeUInt32((uint)cycleMs)));
            AppendAttribute(p, Ids.SubscriptionDisabled, Scalar(DataType.USInt, 0x00));
            AppendAttribute(p, Ids.SubscriptionCount, Scalar(DataType.USInt, 0x00));
            // Two raw big-endian bytes, which is what DataType.Int is everywhere
            // in this protocol and what the Python reference sends.  The value
            // itself is what matters: see DefaultCreditLimit.
            AppendAttribute(p, Ids.SubscriptionCreditLimit,
                            Scalar(DataType.Int, (byte)(creditLimit >> 8), (byte)creditLimit));
            AppendAttribute(p, Ids.SubscriptionTicks, Scalar(DataType.UInt, 0xFF, 0xFF));
            AppendAttribute(p, 1055, Scalar(DataType.USInt, 0x00));

            p.Add((byte)ElementId.TerminatingObject);
            S7Codec.AppendUInt32(p, 0);

            integrityTail = p.Count - requestSetSize;
            return p.ToArray();
        }

        /// <summary>
        /// Notifications the PLC will send before it waits to be given more.
        /// <c>-1</c>, the default, asks for unlimited credit, so the CPU never
        /// stops on its own.
        ///
        /// <para>
        /// The credit limit is flow control: with a positive limit the CPU sends
        /// that many notifications and then goes quiet -- not an error, and not a
        /// closed connection, simply nothing more until its credit is
        /// replenished. Replenishing it is not implemented here, which is why the
        /// default asks for no limit at all.
        /// </para>
        ///
        /// <para>
        /// Measured on an S7-1212C FW V4.6 (2026-11-24): a positive limit is
        /// honored to its <b>low byte only</b>. A limit of 1000 (0x03E8) stops the
        /// CPU after 232 notifications, and 300 (0x012C) after 44; each
        /// notification carries a CreditTick counting up to that number. So any
        /// multiple of 256 asks for a credit of zero and delivers nothing at all,
        /// with no error. With -1 the CreditTick stays 0 and the notifications do
        /// not stop: 1,192 of them over 120 s on a 100 ms cycle, no silence.
        /// Prefer -1; treat a positive value as 8-bit.
        /// </para>
        ///
        /// <para>
        /// The default used to be 1000, which the subscription therefore lost
        /// after 232 notifications -- every ~2 minutes on FlynnProbe's 500 ms
        /// cycle, read as a dropped connection by its watchdog.
        /// </para>
        /// </summary>
        public const short DefaultCreditLimit = -1;

        /// <summary>Build the payload that deletes one subscription container.</summary>
        public static byte[] BuildDeleteSubscriptionRequest(uint subscriptionId, ProtocolVersion protocolVersion)
        {
            var o = new List<byte>();
            S7Codec.AppendUInt32(o, subscriptionId);
            o.Add(0x00);
            o.AddRange(S7Codec.EncodeObjectQualifier(0, protocolVersion));
            S7Codec.AppendUInt32(o, 0);
            return o.ToArray();
        }

        /// <summary>
        /// Decode a notification PValue, including the padded blob form Siemens
        /// uses for subscription values.
        /// </summary>
        private static byte[] DecodeNotificationValue(byte[] data, int offset, out int consumed)
        {
            if (data.Length >= offset + 4 && (data[offset] & 0x10) == 0 &&
                data[offset + 1] == (byte)DataType.Blob && data[offset + 2] == 0)
            {
                uint length = Vlq.DecodeUInt32(data, offset + 3, out int width);
                int valueOffset = offset + 3 + width;
                int valueEnd = valueOffset + (int)length;
                if (valueEnd > data.Length) throw new S7ProtocolException("Subscription blob value is truncated");
                consumed = valueEnd - offset;
                return S7Codec.Slice(data, valueOffset, (int)length);
            }
            return S7Codec.DecodePValueToBytes(data, offset, out consumed);
        }

        /// <summary>
        /// Parse one notification's data section — the frame with its 4-byte
        /// header already stripped.
        /// </summary>
        public static SubscriptionNotification ParseNotification(byte[] data)
        {
            if (data.Length == 0 || data[0] != (byte)Opcode.Notification)
                throw new S7ProtocolException("Expected an S7comm-plus notification");

            int offset = 1;
            if (data.Length < offset + 11)
                throw new S7ProtocolException("Subscription notification header is truncated");

            var n = new SubscriptionNotification
            {
                SubscriptionId = S7Codec.ReadUInt32(data, offset),
            };
            offset += 4;
            offset += 6;                               // three protocol-reserved 16-bit fields

            n.CreditTick = data[offset];
            offset += 1;

            n.SequenceNumber = Vlq.DecodeUInt32(data, offset, out int width);
            offset += width;

            if (offset >= data.Length)
                throw new S7ProtocolException("Subscription notification change counter is missing");

            byte changeCounter = data[offset];
            offset += 1;
            if (changeCounter == 0)
            {
                // A zero in this position is the first byte of an 8-byte timestamp,
                // which the change counter then follows.
                offset -= 1;
                if (data.Length < offset + 9)
                    throw new S7ProtocolException("Subscription notification timestamp is truncated");
                n.Timestamp = S7Codec.ReadUInt64(data, offset);
                offset += 8;
                changeCounter = data[offset];
                offset += 1;
            }
            n.ChangeCounter = changeCounter;

            while (offset < data.Length)
            {
                byte status = data[offset];
                offset += 1;
                if (status == 0) break;

                if (status == 0x92)
                {
                    if (data.Length < offset + 4)
                        throw new S7ProtocolException("Subscription item reference is truncated");
                    uint referenceId = S7Codec.ReadUInt32(data, offset);
                    offset += 4;
                    n.Values[referenceId] = DecodeNotificationValue(data, offset, out int c);
                    offset += c;
                }
                else if (status == 0x9B)
                {
                    uint referenceId = Vlq.DecodeUInt32(data, offset, out int rc);
                    offset += rc;
                    n.Values[referenceId] = DecodeNotificationValue(data, offset, out int c);
                    offset += c;
                }
                else if (status == 0x03 || status == 0x13)
                {
                    if (data.Length < offset + 4)
                        throw new S7ProtocolException("Subscription error reference is truncated");
                    uint referenceId = S7Codec.ReadUInt32(data, offset);
                    offset += 4;
                    n.Errors[referenceId] = status;
                }
                else
                {
                    throw new S7ProtocolException($"Unsupported subscription item status 0x{status:X2}");
                }
            }

            return n;
        }
    }
}
