package engine.exchange.pkg.ike.message


enum class IKEPayloadType(val value: UByte) {
    NoNext(0u),
    TypeSA(33u),
    TypeKE(34u),
    TypeIDi(35u),
    TypeIDr(36u),
    TypeCERT(37u),
    TypeCERTreq(38u),
    TypeAUTH(39u),
    TypeNiNr(40u),
    TypeN(41u),
    TypeD(42u),
    TypeV(43u),
    TypeTSi(44u),
    TypeTSr(45u),
    TypeSK(46u),
    TypeCP(47u),
    TypeEAP(48u)
}

enum class EAPType(val value: UByte) {
    EAPTypeIdentity(1u),
    EAPTypeNotification(2u),
    EAPTypeNak(3u),
    EAPTypeExpanded(254u)
}

enum class EAPCode(val value: UByte) {
    EAPCodeRequest(1u),
    EAPCodeResponse(2u),
    EAPCodeSuccess(3u),
    EAPCodeFailure(4u)
}

enum class PayloadType(val value: UInt) {
    TypeEncryptionAlgorithm(1u),
    TypePseudorandomFunction(2u),
    TypeIntegrityAlgorithm(3u),
    TypeDiffieHellmanGroup(4u),
    TypeExtendedSequenceNumbers(5u)
}

enum class AttributeFormat(val value: UInt) {
    AttributeFormatUseTLV(0u),
    AttributeFormatUseTV(1u)
}

enum class AttributeType(val value: UInt) {
    AttributeTypeKeyLength(14u)
}

enum class EncryptionAlgorithm(val value: UInt) {
    ENCR_DES_IV64(1u),
    ENCR_DES(2u),
    ENCR_3DES(3u),
    ENCR_RC5(4u),
    ENCR_IDEA(5u),
    ENCR_CAST(6u),
    ENCR_BLOWFISH(7u),
    ENCR_3IDEA(8u),
    ENCR_DES_IV32(9u),
    ENCR_NULL(11u),
    ENCR_AES_CBC(12u),
    ENCR_AES_CTR(13u)
}

enum class PRFAlgorithm(val value: UInt) {
    PRF_HMAC_MD5(1u),
    PRF_HMAC_SHA1(2u),
    PRF_HMAC_TIGER(3u)
}

enum class AuthenticationAlgorithm(val value: UInt) {
    AUTH_NONE(0u),
    AUTH_HMAC_MD5_96(1u),
    AUTH_HMAC_SHA1_96(2u),
    AUTH_DES_MAC(3u),
    AUTH_KPDK_MD5(4u),
    AUTH_AES_XCBC_96(5u)
}

enum class DiffieHellmanGroup(val value: UInt) {
    DH_NONE(0u),
    DH_768_BIT_MODP(1u),
    DH_1024_BIT_MODP(2u),
    DH_1536_BIT_MODP(5u),
    DH_2048_BIT_MODP(14u),
    DH_3072_BIT_MODP(15u),
    DH_4096_BIT_MODP(16u),
    DH_6144_BIT_MODP(17u),
    DH_8192_BIT_MODP(18u)
}

enum class ESNOption(val value: UInt) {
    ESN_NO(0u),
    ESN_NEED(1u)
}

enum class TrafficSelectorType(val value: UInt) {
    TS_IPV4_ADDR_RANGE(7u),
    TS_IPV6_ADDR_RANGE(8u)
}

enum class ExchangeType(val value: UInt) {
    IKE_SA_INIT(34u),
    IKE_AUTH(35u),
    CREATE_CHILD_SA(36u),
    INFORMATIONAL(37u)
}

enum class NotifyMessageType(val value: UInt) {
    UNSUPPORTED_CRITICAL_PAYLOAD(1u),
    INVALID_IKE_SPI(4u),
    INVALID_MAJOR_VERSION(5u),
    INVALID_SYNTAX(7u),
    INVALID_MESSAGE_ID(9u),
    INVALID_SPI(11u),
    NO_PROPOSAL_CHOSEN(14u),
    INVALID_KE_PAYLOAD(17u),
    AUTHENTICATION_FAILED(24u),
    SINGLE_PAIR_REQUIRED(34u),
    NO_ADDITIONAL_SAS(35u),
    INTERNAL_ADDRESS_FAILURE(36u),
    FAILED_CP_REQUIRED(37u),
    TS_UNACCEPTABLE(38u),
    INVALID_SELECTORS(39u),
    TEMPORARY_FAILURE(43u),
    CHILD_SA_NOT_FOUND(44u),
    INITIAL_CONTACT(16384u),
    SET_WINDOW_SIZE(16385u),
    ADDITIONAL_TS_POSSIBLE(16386u),
    IPCOMP_SUPPORTED(16387u),
    NAT_DETECTION_SOURCE_IP(16388u),
    NAT_DETECTION_DESTINATION_IP(16389u),
    COOKIE(16390u),
    USE_TRANSPORT_MODE(16391u),
    HTTP_CERT_LOOKUP_SUPPORTED(16392u),
    REKEY_SA(16393u),
    ESP_TFC_PADDING_NOT_SUPPORTED(16394u),
    NON_FIRST_FRAGMENTS_ALSO(16395u)
}

enum class ProtocolType(val value: UInt) {
    TypeNone(0u),
    TypeIKE(1u),
    TypeAH(2u),
    TypeESP(3u)
}

enum class Flag(val value: UInt) {
    ResponseBitCheck(0x20u),
    VersionBitCheck(0x10u),
    InitiatorBitCheck(0x08u)
}

enum class CertificateType(val value: UInt) {
    PKCS7WrappedX509Certificate(1u),
    PGPCertificate(2u),
    DNSSignedKey(3u),
    X509CertificateSignature(4u),
    KerberosToken(6u),
    CertificateRevocationList(7u),
    AuthorityRevocationList(8u),
    SPKICertificate(9u),
    X509CertificateAttribute(10u),
    HashAndURLOfX509Certificate(12u),
    HashAndURLOfX509Bundle(13u)
}

enum class IdentificationType(val value: UInt) {
    ID_IPV4_ADDR(1u),
    ID_FQDN(2u),
    ID_RFC822_ADDR(3u),
    ID_IPV6_ADDR(5u),
    ID_DER_ASN1_DN(9u),
    ID_DER_ASN1_GN(10u),
    ID_KEY_ID(11u)
}

enum class SignatureType(val value: UInt) {
    RSADigitalSignature(1u),
    SharedKeyMesageIntegrityCode(2u),
    DSSDigitalSignature(3u)
}

enum class ConfigurationMessageType(val value: UInt) {
    CFG_REQUEST(1u),
    CFG_REPLY(2u),
    CFG_SET(3u),
    CFG_ACK(4u)
}

enum class ConfigurationAttributeType(val value: UInt) {
    INTERNAL_IP4_ADDRESS(1u),
    INTERNAL_IP4_NETMASK(2u),
    INTERNAL_IP4_DNS(3u),
    INTERNAL_IP4_NBNS(4u),
    INTERNAL_IP4_DHCP(6u),
    APPLICATION_VERSION(7u),
    INTERNAL_IP6_ADDRESS(8u),
    INTERNAL_IP6_DNS(10u),
    INTERNAL_IP6_DHCP(12u),
    INTERNAL_IP4_SUBNET(13u),
    SUPPORTED_ATTRIBUTES(14u),
    INTERNAL_IP6_SUBNET(15u)
}

enum class IPProtocol(val value: UInt) {
    IPProtocolAll(0u),
    IPProtocolICMP(1u),
    IPProtocolTCP(6u),
    IPProtocolUDP(17u),
    IPProtocolGRE(47u)
}

const val VendorID3GPP = 10415

const val VendorTypeEAP5G = 3

enum class EAP5GType(val value: UInt) {
    EAP5GType5GStart(1u),
    EAP5GType5GNAS(2u),
    EAP5GType5GStop(4u)
}

enum class ANParametersType(val value: UInt) {
    ANParametersTypeGUAMI(1u),
    ANParametersTypeSelectedPLMNID(2u),
    ANParametersTypeRequestedNSSAI(3u),
    ANParametersTypeEstablishmentCause(4u)
}

const val ANParametersLenGUAMI = 6
const val ANParametersLenPLMNID = 3
const val ANParametersLenEstCause = 1

enum class EstablishmentCause(val value: UInt) {
    EstablishmentCauseEmergency(0u),
    EstablishmentCauseHighPriorityAccess(1u),
    EstablishmentCauseMO_Signalling(3u),
    EstablishmentCauseMO_Data(4u),
    EstablishmentCauseMPS_PriorityAccess(8u),
    EstablishmentCauseMCS_PriorityAccess(9u)
}

const val EAP5GSpareValue = 0

const val Vendor3GPPNotifyType5G_QOS_INFO: UShort = 55501u
const val Vendor3GPPNotifyTypeNAS_IP4_ADDRESS: UShort = 55502u
const val Vendor3GPPNotifyTypeUP_IP4_ADDRESS: UShort = 55504u
const val Vendor3GPPNotifyTypeNAS_TCP_PORT: UShort = 55506u

const val NotifyType5G_QOS_INFOBitDSCPICheck: Byte = 1
const val NotifyType5G_QOS_INFOBitDCSICheck: Byte = 1 shl 1


