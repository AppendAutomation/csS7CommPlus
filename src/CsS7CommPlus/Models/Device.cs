using System.Collections.Generic;

namespace CsS7CommPlus.Models
{
    /// <summary>
    /// CPU identity decoded from the CreateObject response (spec §7).
    /// Direct port of the Python Device.
    /// </summary>
    public class Device
    {
        /// <summary>Reported serial number.</summary>
        public string? Serial { get; set; }
        /// <summary>Firmware build string (e.g. "OMSP_12.00.02.11_35.11.00.01").</summary>
        public string? Firmware { get; set; }
        /// <summary>Order number (e.g. "1;6ES7 212-1HE40-0XB0 ;V4.6").</summary>
        public string? OrderNumber { get; set; }
        /// <summary>Firmware version (e.g. "V4.6").</summary>
        public string? Version { get; set; }
        /// <summary>Type id string.</summary>
        public string? TypeId { get; set; }
        /// <summary>All clear-text strings scanned from the response.</summary>
        public List<string> RawStrings { get; set; } = new List<string>();

        /// <summary>Summary string.</summary>
        public override string ToString() =>
            $"Device(OrderNumber={OrderNumber}, Version={Version}, Firmware={Firmware}, Serial={Serial})";
    }
}
