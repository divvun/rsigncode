use const_oid::ObjectIdentifier;

// Microsoft OID Authenticode
pub const SPC_INDIRECT_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");
pub const SPC_STATEMENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.11");
pub const SPC_SP_OPUS_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.12");
pub const SPC_PE_IMAGE_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.15");
pub const SPC_CAB_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.25");
pub const SPC_SIPINFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.30");
pub const SPC_PE_IMAGE_PAGE_HASHES_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.3.1");
pub const SPC_PE_IMAGE_PAGE_HASHES_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.3.2");
pub const SPC_NESTED_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");

// Microsoft OID Time Stamping
pub const SPC_TIME_STAMP_REQUEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.2.1");
pub const SPC_RFC3161: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

// Microsoft OID Crypto 2.0
pub const MS_CTL: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.1");

// Microsoft OID Catalog
pub const CAT_NAMEVALUE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.12.2.1");

// Unauthenticated data blob
pub const SPC_UNAUTHENTICATED_DATA_BLOB: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.42921.1.2.1");

// PKCS#9 attributes
pub const PKCS9_COUNTER_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");
pub const PKCS9_SIGNING_TIME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

// PKCS#7 data
pub const PKCS7_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

// Code signing statement types
pub const SPC_INDIVIDUAL_SP_KEY_PURPOSE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.21");
pub const SPC_COMMERCIAL_SP_KEY_PURPOSE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.22");
