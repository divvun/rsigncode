use const_oid::ObjectIdentifier;
use der::asn1::{BitString, Ia5String, OctetString};
use der::{Any, Sequence, Choice};
use x509_cert::spki::AlgorithmIdentifierOwned;

/// SpcIndirectDataContent — the signed content in an Authenticode signature.
///
/// ```asn1
/// SpcIndirectDataContent ::= SEQUENCE {
///     data  SpcAttributeTypeAndOptionalValue,
///     messageDigest DigestInfo
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcIndirectDataContent {
    pub data: SpcAttributeTypeAndOptionalValue,
    pub message_digest: DigestInfo,
}

/// ```asn1
/// SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
///     type  OBJECT IDENTIFIER,
///     value [0] EXPLICIT ANY OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcAttributeTypeAndOptionalValue {
    pub obj_type: ObjectIdentifier,
    pub value: Option<Any>,
}

/// ```asn1
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest          OCTET STRING
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DigestInfo {
    pub digest_algorithm: AlgorithmIdentifierOwned,
    pub digest: OctetString,
}

/// ```asn1
/// SpcPeImageData ::= SEQUENCE {
///     flags  BIT STRING,
///     file   [0] EXPLICIT SpcLink OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcPeImageData {
    pub flags: BitString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub file: Option<SpcLink>,
}

/// ```asn1
/// SpcLink ::= CHOICE {
///     url     [0] IMPLICIT IA5String,
///     moniker [1] IMPLICIT SpcSerializedObject,
///     file    [2] EXPLICIT SpcString
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SpcLink {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Url(Ia5String),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    Moniker(SpcSerializedObject),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    File(SpcString),
}

/// ```asn1
/// SpcSerializedObject ::= SEQUENCE {
///     classId    OCTET STRING,
///     serializedData OCTET STRING
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcSerializedObject {
    pub class_id: OctetString,
    pub serialized_data: OctetString,
}

/// ```asn1
/// SpcString ::= CHOICE {
///     unicode [0] IMPLICIT BMPString,
///     ascii   [1] IMPLICIT IA5String
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SpcString {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Unicode(der::asn1::BmpString),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    Ascii(Ia5String),
}

/// ```asn1
/// SpcSpOpusInfo ::= SEQUENCE {
///     programName [0] EXPLICIT SpcString OPTIONAL,
///     moreInfo    [1] EXPLICIT SpcLink OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcSpOpusInfo {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub program_name: Option<SpcString>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub more_info: Option<SpcLink>,
}

/// ```asn1
/// SpcSipInfo ::= SEQUENCE {
///     a  INTEGER,
///     string OCTET STRING,
///     b  INTEGER,
///     c  INTEGER,
///     d  INTEGER,
///     e  INTEGER,
///     f  INTEGER
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcSipInfo {
    pub a: der::asn1::Int,
    pub string: OctetString,
    pub b: der::asn1::Int,
    pub c: der::asn1::Int,
    pub d: der::asn1::Int,
    pub e: der::asn1::Int,
    pub f: der::asn1::Int,
}

/// Page hash class ID used to identify SpcSerializedObject containing page hashes.
pub const PAGE_HASH_CLASS_ID: [u8; 16] = [
    0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66,
    0xae, 0x05, 0xa2, 0x17, 0xda, 0x8e, 0x60, 0xd6,
];
