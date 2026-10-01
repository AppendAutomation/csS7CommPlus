using System.Collections.Generic;

namespace CsS7CommPlus.Models
{
    /// <summary>
    /// Response returned by all PLC operations: tag name, value and status.
    /// Direct port of the Python Response (pylogix-style).
    /// </summary>
    public class Response
    {
        /// <summary>The tag that was read or written (null for session-level ops).</summary>
        public string? TagName { get; }

        /// <summary>The value read from or written to the tag.</summary>
        public object? Value { get; }

        /// <summary>Operation status; "Success" on success.</summary>
        public string Status { get; }

        /// <summary>True when the operation succeeded.</summary>
        public bool IsSuccess => Status == "Success";

        /// <summary>Create a response from a tag name, value and status (code or message).</summary>
        public Response(string? tagName, object? value, object status)
        {
            TagName = tagName;
            Value = value;
            Status = GetErrorString(status);
        }

        /// <summary>Resolve an int status/return-value or an already-formatted string.</summary>
        public static string GetErrorString(object status)
        {
            if (status is string s) return s;
            long code;
            if (status is byte b) code = b;
            else if (status is int i) code = i;
            else if (status is long l) code = l;
            else return "Unknown error " + status;

            if (S7PlusErrorCodes.TryGetValue(code, out var msg)) return msg;
            return string.Format("S7comm-plus error 0x{0:x}", code);
        }

        /// <summary>"TagName Value Status".</summary>
        public override string ToString() => $"{TagName} {Value} {Status}";

        /// <summary>
        /// S7comm-plus return/error values.  0x00 and the write-success marker
        /// 0x34 (spec §12) both mean success.
        /// </summary>
        public static readonly Dictionary<long, string> S7PlusErrorCodes = new Dictionary<long, string>
        {
            { 0x00, "Success" },
            { 0x34, "Success" },
        };
    }
}
