use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::Sequence;

/// Authenticode TimeStampRequest — wraps the encrypted digest for legacy timestamp protocol.
///
/// ```asn1
/// TimeStampRequest ::= SEQUENCE {
///     type  OBJECT IDENTIFIER,  -- SPC_TIME_STAMP_REQUEST (1.3.6.1.4.1.311.3.2.1)
///     blob  TimeStampRequestBlob
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampRequest {
    pub req_type: ObjectIdentifier,
    pub blob: TimeStampRequestBlob,
}

/// ```asn1
/// TimeStampRequestBlob ::= SEQUENCE {
///     type       OBJECT IDENTIFIER,  -- pkcs7-data (1.2.840.113549.1.7.1)
///     signature  [0] EXPLICIT OCTET STRING
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampRequestBlob {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub signature: OctetString,
}
