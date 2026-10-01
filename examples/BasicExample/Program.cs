using System;
using CsS7CommPlus;

namespace BasicExample
{
    /// <summary>
    /// Basic usage of CsS7CommPlus, mirroring the pyS7commplus examples.
    ///
    ///   dotnet run --project examples/BasicExample 192.168.2.50
    /// </summary>
    internal static class Program
    {
        private static void Main(string[] args)
        {
            var ip = args.Length > 0 ? args[0] : "192.168.2.50";

            using var comm = new PLC(ip);

            // Clear-text protocol-version-1 identity probe (works with no V3 backend).
            var ident = comm.GetDeviceProperties();
            Console.WriteLine("GetDeviceProperties: " + ident.Status);
            if (ident.Value is CsS7CommPlus.Models.Device dev)
                Console.WriteLine("  " + dev);

            // Explore / Read / Write run on the integrity-protected V3 session.
            // Wire a V3 backend (HarpoS7 / S7CommPlusDriver) to enable them:
            //
            //   comm.V3BackendFactory = plc => new MyS7CommPlusDriverBackend(plc);
            //
            // Without one, the V3 calls return a clear status:
            var r = comm.Read("SPDL BLU Winder DB.driveKp");
            Console.WriteLine("Read: " + r);
        }
    }
}
