using System;
using System.Collections.Generic;

namespace CsS7CommPlus.V3.Protocol
{
    /// <summary>
    /// Variable-length quantity (VLQ) encoding used throughout S7comm-plus framing.
    ///
    /// Each byte carries 7 data bits plus a continuation bit in the MSB, most
    /// significant group first.  Signed forms use bit 6 of the first byte as the
    /// sign flag.  The 64-bit forms have a special case: eight 7-bit groups give
    /// only 56 bits, so a ninth byte carries a full 8 data bits with no
    /// continuation flag.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (vlq.py).
    /// </summary>
    public static class Vlq
    {
        /// <summary>Encode an unsigned 32-bit value (1-5 bytes).</summary>
        public static byte[] EncodeUInt32(uint value)
        {
            int numGroups = 1;
            for (int i = 4; i > 0; i--)
            {
                if ((value & (0x7FUL << (i * 7))) != 0) { numGroups = i + 1; break; }
            }

            var result = new byte[numGroups];
            for (int i = numGroups - 1, o = 0; i >= 0; i--, o++)
            {
                byte group = (byte)((value >> (i * 7)) & 0x7F);
                if (i > 0) group |= 0x80;
                result[o] = group;
            }
            return result;
        }

        /// <summary>Decode an unsigned 32-bit value; <paramref name="consumed"/> receives the byte count.</summary>
        public static uint DecodeUInt32(byte[] data, int offset, out int consumed)
        {
            uint value = 0;
            consumed = 0;
            for (int i = 0; i < 5; i++)
            {
                if (offset + consumed >= data.Length) throw new S7ProtocolException("Unexpected end of VLQ data");
                byte octet = data[offset + consumed];
                consumed++;
                value = (value << 7) | (uint)(octet & 0x7F);
                if ((octet & 0x80) == 0) break;
            }
            return value;
        }

        /// <summary>Encode a signed 32-bit value (1-5 bytes).</summary>
        public static byte[] EncodeInt32(int value)
        {
            long absV = value == int.MinValue ? 0x80000000L : Math.Abs((long)value);

            var b = new byte[5];
            b[0] = (byte)(value & 0x7F);
            int length = 1;
            int shifted = value;

            for (int i = 1; i < 5; i++)
            {
                if (absV >= 0x40)
                {
                    length++;
                    absV >>= 7;
                    shifted >>= 7;
                    b[i] = (byte)(((shifted & 0x7F) + 0x80) & 0xFF);
                }
                else break;
            }

            var result = new byte[length];
            for (int i = length - 1, o = 0; i >= 0; i--, o++) result[o] = b[i];
            return result;
        }

        /// <summary>Decode a signed 32-bit value.</summary>
        public static int DecodeInt32(byte[] data, int offset, out int consumed)
        {
            int value = 0;
            consumed = 0;
            for (int counter = 1; counter <= 5; counter++)
            {
                if (offset + consumed >= data.Length) throw new S7ProtocolException("Unexpected end of VLQ data");
                byte octet = data[offset + consumed];
                consumed++;

                if (counter == 1 && (octet & 0x40) != 0)
                {
                    octet &= 0xBF;
                    value = -64;              // pre-load with the one's complement
                }
                else
                {
                    value <<= 7;
                }

                value += octet & 0x7F;
                if ((octet & 0x80) == 0) break;
            }
            return value;
        }

        /// <summary>Encode an unsigned 64-bit value (1-9 bytes).</summary>
        public static byte[] EncodeUInt64(ulong value)
        {
            bool special = value > 0x00FFFFFFFFFFFFFFUL;

            var b = new byte[9];
            b[0] = special ? (byte)(value & 0xFF) : (byte)(value & 0x7F);

            int length = 1;
            for (int i = 1; i < 9; i++)
            {
                if (value >= 0x80)
                {
                    length++;
                    value >>= (i == 1 && special) ? 8 : 7;
                    b[i] = (byte)(((value & 0x7F) + 0x80) & 0xFF);
                }
                else break;
            }

            if (special && length == 8) { length++; b[8] = 0x80; }

            var result = new byte[length];
            for (int i = length - 1, o = 0; i >= 0; i--, o++) result[o] = b[i];
            return result;
        }

        /// <summary>Decode an unsigned 64-bit value.</summary>
        public static ulong DecodeUInt64(byte[] data, int offset, out int consumed)
        {
            ulong value = 0;
            consumed = 0;
            int cont = 0;

            for (int counter = 1; counter <= 8; counter++)
            {
                if (offset + consumed >= data.Length) throw new S7ProtocolException("Unexpected end of VLQ data");
                byte octet = data[offset + consumed];
                consumed++;
                value = (value << 7) | (uint)(octet & 0x7F);
                cont = octet & 0x80;
                if (cont == 0) break;
            }

            if (cont != 0)
            {
                if (offset + consumed >= data.Length) throw new S7ProtocolException("Unexpected end of VLQ data");
                byte octet = data[offset + consumed];
                consumed++;
                value = (value << 8) | octet;    // ninth byte carries all 8 bits
            }
            return value;
        }

        /// <summary>Encode a signed 64-bit value (1-9 bytes).</summary>
        public static byte[] EncodeInt64(long value)
        {
            ulong absV = value == long.MinValue ? 0x8000000000000000UL : (ulong)Math.Abs(value);
            bool special = absV > 0x007FFFFFFFFFFFFFUL;

            var b = new byte[9];
            b[0] = special ? (byte)(value & 0xFF) : (byte)(value & 0x7F);

            int length = 1;
            long shifted = value;
            for (int i = 1; i < 9; i++)
            {
                if (absV >= 0x40)
                {
                    length++;
                    if (i == 1 && special) { absV >>= 8; shifted >>= 8; }
                    else { absV >>= 7; shifted >>= 7; }
                    b[i] = (byte)(((shifted & 0x7F) + 0x80) & 0xFF);
                }
                else break;
            }

            if (special && length == 8) { length++; b[8] = value >= 0 ? (byte)0x80 : (byte)0xFF; }

            var result = new byte[length];
            for (int i = length - 1, o = 0; i >= 0; i--, o++) result[o] = b[i];
            return result;
        }

        /// <summary>Decode a signed 64-bit value.</summary>
        public static long DecodeInt64(byte[] data, int offset, out int consumed)
        {
            long value = 0;
            consumed = 0;
            int cont = 0;

            for (int counter = 1; counter <= 8; counter++)
            {
                if (offset + consumed >= data.Length) throw new S7ProtocolException("Unexpected end of VLQ data");
                byte octet = data[offset + consumed];
                consumed++;

                if (counter == 1 && (octet & 0x40) != 0)
                {
                    octet &= 0xBF;
                    value = -64;
                }
                else
                {
                    value <<= 7;
                }

                cont = octet & 0x80;
                value += octet & 0x7F;
                if (cont == 0) break;
            }

            if (cont != 0)
            {
                if (offset + consumed >= data.Length) throw new S7ProtocolException("Unexpected end of VLQ data");
                byte octet = data[offset + consumed];
                consumed++;
                value = (value << 8) | octet;
            }
            return value;
        }

        /// <summary>Append a VLQ-encoded unsigned 32-bit value to a buffer.</summary>
        public static void AppendUInt32(List<byte> buffer, uint value) => buffer.AddRange(EncodeUInt32(value));

        /// <summary>Append a VLQ-encoded unsigned 64-bit value to a buffer.</summary>
        public static void AppendUInt64(List<byte> buffer, ulong value) => buffer.AddRange(EncodeUInt64(value));
    }
}
