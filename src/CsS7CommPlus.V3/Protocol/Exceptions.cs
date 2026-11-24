using System;

namespace CsS7CommPlus.V3.Protocol
{
    /// <summary>Base class for every S7comm-plus V3 failure.</summary>
    public class S7Exception : Exception
    {
        /// <summary>Create the exception with a message.</summary>
        public S7Exception(string message) : base(message) { }
        /// <summary>Create the exception with a message and inner cause.</summary>
        public S7Exception(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>The socket, COTP or session could not be established or was lost.</summary>
    public class S7ConnectionException : S7Exception
    {
        /// <summary>Create the exception with a message.</summary>
        public S7ConnectionException(string message) : base(message) { }
        /// <summary>Create the exception with a message and inner cause.</summary>
        public S7ConnectionException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>
    /// CreateObject came back without a ServerSessionVersion attribute. Some
    /// firmware answers the full TIA-Portal-style identification that way;
    /// the connect path retries with the minimal ClientRID-only request.
    /// </summary>
    public class S7MissingSessionVersionException : S7ConnectionException
    {
        /// <summary>Create the exception with a message.</summary>
        public S7MissingSessionVersionException(string message) : base(message) { }
    }

    /// <summary>A frame did not match the protocol the PLC is expected to speak.</summary>
    public class S7ProtocolException : S7Exception
    {
        /// <summary>Create the exception with a message.</summary>
        public S7ProtocolException(string message) : base(message) { }
    }

    /// <summary>A V3 frame failed its keyed-digest check; the session must be re-established.</summary>
    public class S7IntegrityException : S7ProtocolException
    {
        /// <summary>Create the exception with a message.</summary>
        public S7IntegrityException(string message) : base(message) { }
    }

    /// <summary>A read or the connect handshake did not complete in time.</summary>
    public class S7TimeoutException : S7Exception
    {
        /// <summary>Create the exception with a message.</summary>
        public S7TimeoutException(string message) : base(message) { }
    }

    /// <summary>The PLC rejected the session key, the certificate or the password.</summary>
    public class S7AuthenticationException : S7Exception
    {
        /// <summary>Create the exception with a message.</summary>
        public S7AuthenticationException(string message) : base(message) { }
        /// <summary>Create the exception with a message and inner cause.</summary>
        public S7AuthenticationException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>A response arrived for a sequence number that has already been handled.</summary>
    public class S7StalePacketException : S7ProtocolException
    {
        /// <summary>Create the exception with a message.</summary>
        public S7StalePacketException(string message) : base(message) { }
    }
}
