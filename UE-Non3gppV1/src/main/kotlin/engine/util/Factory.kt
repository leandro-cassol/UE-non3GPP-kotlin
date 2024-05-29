package engine.util

import config.Config
import engine.exchange.pkg.context.N3iwfUe
import engine.exchange.pkg.ike.handler.RandomNumberGenerator.generateRandomNumber
import engine.exchange.pkg.ike.handler.group14Generator
import engine.exchange.pkg.ike.message.*
import engine.ran.RanUeContext
import free5gc.nas.nasType.MobileIdentity5GS
import free5gc.nas.security.AlgCiphering128NEA0
import free5gc.nas.security.AlgIntegrity128NIA2
import free5gc.openapi.models.*
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

private val log = LoggerFactory.getLogger("Security")

fun createRanUEContext(cfg: Config): RanUeContext {
    val ue = RanUeContext.newRanUeContext(
        getSupi(cfg),
        cfg.ue.ranUeNgapId,
        AlgCiphering128NEA0,
        AlgIntegrity128NIA2,
        AccessType.AccessType_NON_3_GPP_ACCESS
    )
    ue.amfUeNgapId = cfg.ue.amfUeNgapId
    ue.authenticationSubs = createAuthSubscription(cfg)
    return ue
}

fun getSupi(cfg: Config): String {
    val supi = "imsi-${cfg.ue.hplmn.mcc}${cfg.ue.hplmn.mnc}${cfg.ue.msin}"
    return supi
}

fun createAuthSubscription(cfg: Config): AuthenticationSubscription {
    val authSubs = AuthenticationSubscription()
    authSubs.permanentKey = PermanentKey().apply { permanentKeyValue = cfg.ue.authSubscription.permanentKeyValue}
    authSubs.opc = Opc().apply {opcValue = cfg.ue.authSubscription.opcValue}
    authSubs.milenage = Milenage().apply {
        op = Op().apply { opValue = cfg.ue.authSubscription.opValue}
    }
    authSubs.authenticationManagementField = cfg.ue.authenticationManagementField
    authSubs.sequenceNumber = cfg.ue.authSubscription.sequenceNumber
    authSubs.authenticationMethod = AuthMethod.AuthMethod__5_G_AKA
    return authSubs
}

fun createMobileIdentity(cfg: Config): MobileIdentity5GS {
    val (suciV1, suciV2, suciV3, suciV4) = encodeUeSuci(cfg)
    val resu = getMccAndMncInOctets(cfg)
    if (cfg.ue.msin.length == 8) {
        return MobileIdentity5GS().apply {
            len = 12u
            buffer = ubyteArrayOf(0x01u, resu[0].toUByte(), resu[1].toUByte(), resu[2].toUByte(), 0xf0u ,
                0xffu, 0x00u, 0x00u, suciV4.toUByte(), suciV3.toUByte(), suciV2.toUByte(), suciV1.toUByte())
        }
    } else {
        throw Exception("${cfg.ue.msin} size not supported!")
    }
}

fun encodeUeSuci(cfg: Config): Quadruple<Byte, Byte, Byte, Byte> {
    val aux = cfg.ue.msin.reversed()
    val suci = aux.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    if (cfg.ue.msin.length == 8) {
        return Quadruple(suci[0], suci[1], suci[2], suci[3])
    } else {
        throw Exception("${cfg.ue.msin} size not supported!")
    }
}

fun getMccAndMncInOctets(cfg: Config): ByteArray {
    val mcc = cfg.ue.hplmn.mcc.reversed()
    val mnc = cfg.ue.hplmn.mnc.reversed()
    val oct5 = mcc.substring(1, 3)
    val oct6: String
    val oct7: String
    if (cfg.ue.hplmn.mnc.length == 2) {
        oct6 = "f${mcc[0]}"
        oct7 = mnc
    } else {
        oct6 = "${mnc[0]}${mcc[0]}"
        oct7 = mnc.substring(1, 3)
    }
    val resu = (oct5 + oct6 + oct7).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    return resu
}

fun createN3IWFUe(): N3iwfUe {
    val n3ue = N3iwfUe()
    n3ue.pduSessionList = mutableMapOf()
    n3ue.n3iwfChildSecurityAssociation = mutableMapOf()
    n3ue.temporaryExchangeMsgIDChildSAMapping = mutableMapOf()
    return n3ue
}

fun createN3IWFIKEConnectionIP(cfg: Config): InetAddress {
    val address = cfg.n3iwfInfo.ikeBindAddress
    val udpAddr = InetAddress.getByName(address)
    return udpAddr
}

fun createN3IWFIKEConnectionPort(cfg: Config): String {
    return cfg.n3iwfInfo.ikeBindPort
}

fun createUEUDPListener(cfg: Config): DatagramSocket {
    val socketAddress = InetSocketAddress(cfg.ue.localPublicIPAddr, cfg.ue.localPublicPortUDPConnection.toInt())
    val udpListener = DatagramSocket(socketAddress)
    return udpListener
}

fun createIKEMessageSAInit(): Pair<IKEMessage, Proposal> {
    val ikeInitiatorSPI = createIKEInitiatorSPI()
    val ikeMessage = IKEMessage()
    ikeMessage.buildIKEHeader(ikeInitiatorSPI, 0u, ExchangeType.IKE_SA_INIT.value.toUByte(), Flag.InitiatorBitCheck.value.toUByte(), 0u)
    val securityAssociation = ikeMessage.payloads.buildSecurityAssociation()
    val proposal = securityAssociation.proposals.buildProposal(1u, ProtocolType.TypeIKE.value.toUByte(), ByteArray(0))

    // ENCR
    val attributeType: UShort = AttributeType.AttributeTypeKeyLength.value.toUShort()
    val keyLength: UShort = 256u
    proposal.encryptionAlgorithm.buildTransform(PayloadType.TypeEncryptionAlgorithm.value.toUByte(), EncryptionAlgorithm.ENCR_AES_CBC.value.toUShort(), attributeType, keyLength, ByteArray(0))
    // INTEG
    proposal.integrityAlgorithm.buildTransform(PayloadType.TypeIntegrityAlgorithm.value.toUByte(), AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value.toUShort(), null, null, ByteArray(0))
    // PRF
    proposal.pseudorandomFunction.buildTransform(PayloadType.TypePseudorandomFunction.value.toUByte(), PRFAlgorithm.PRF_HMAC_SHA1.value.toUShort(), null, null, ByteArray(0))
    // DH
    proposal.diffieHellmanGroup.buildTransform(PayloadType.TypeDiffieHellmanGroup.value.toUByte(), DiffieHellmanGroup.DH_2048_BIT_MODP.value.toUShort(), null, null, ByteArray(0))

    return Pair(ikeMessage, proposal)
}

fun createIKEInitiatorSPI(): ULong {
    return 123123u
}

fun buildInitIKEMessageData(ikeMessage: IKEMessage): Quadruple<BigInteger, BigInteger, ByteArray, ByteArray> {
    val secret: BigInteger = generateRandomNumber()

    //val factor = BigInteger(engine.exchange.pkg.ike.handler.group14PrimeString, 16)
    // Ao usar group14PrimeString, estava gerando um BigInteger de 257 Bytes.
    // Assim, o BigInteger a partir dos Bytes gerados na execução do UE em GO
    val factorByteArray = strToByteArray("255 255 255 255 255 255 255 255 201 15 218 162 33 104 194 52 196 198 98 139 128 220 28 209 41 2 78 8 138 103 204 116 2 11 190 166 59 19 155 34 81 74 8 121 142 52 4 221 239 149 25 179 205 58 67 27 48 43 10 109 242 95 20 55 79 225 53 109 109 81 194 69 228 133 181 118 98 94 126 198 244 76 66 233 166 55 237 107 11 255 92 182 244 6 183 237 238 56 107 251 90 137 159 165 174 159 36 17 124 75 31 230 73 40 102 81 236 228 91 61 194 0 124 184 161 99 191 5 152 218 72 54 28 85 211 154 105 22 63 168 253 36 207 95 131 101 93 35 220 163 173 150 28 98 243 86 32 133 82 187 158 213 41 7 112 150 150 109 103 12 53 78 74 188 152 4 241 116 108 8 202 24 33 124 50 144 94 70 46 54 206 59 227 158 119 44 24 14 134 3 155 39 131 162 236 7 162 143 181 197 93 240 111 76 82 201 222 43 203 246 149 88 23 24 57 149 73 124 234 149 106 229 21 210 38 24 152 250 5 16 21 114 142 90 138 172 170 104 255 255 255 255 255 255 255 255")
    val factor = factorByteArray.toBigInteger()

    val generator = BigInteger.valueOf(group14Generator.toLong())
    val valAux = generator.modPow(secret, factor)
    val localPublicKeyExchangeValue: ByteArray = valAux.toByteArray().removeZero()

    val prependZero = ByteArray(factor.toByteArray().size - localPublicKeyExchangeValue.size)
    var localPublicKeyExchangeValuePadded = prependZero + localPublicKeyExchangeValue
    localPublicKeyExchangeValuePadded = localPublicKeyExchangeValuePadded.removeZero()

    ikeMessage.payloads.buildKeyExchange(DiffieHellmanGroup.DH_2048_BIT_MODP.value.toShort(), localPublicKeyExchangeValuePadded)
    val localNonce = generateRandomNumber().toByteArray()

    ikeMessage.payloads.buildNonce(localNonce)
    val ikeMessageData = ikeMessage.encode()
    return Quadruple(secret, factor, localNonce, ikeMessageData)
}


fun createEAP5GANParameters(): ByteArray {
    val anParameters = mutableListOf<Byte>()
    val guami = byteArrayOf(0x02, (0xf8).toByte(), 0x39, (0xca).toByte(), (0xfe).toByte(), 0x0)
    val guamiParameter = byteArrayOf(ANParametersType.ANParametersTypeGUAMI.value.toByte(), guami.size.toByte()) + guami
    anParameters.addAll(guamiParameter.toList())
    val establishmentCause = byteArrayOf(EstablishmentCause.EstablishmentCauseMO_Signalling.value.toByte())
    val establishmentCauseParameter = byteArrayOf(ANParametersType.ANParametersTypeEstablishmentCause.value.toByte(), establishmentCause.size.toByte()) + establishmentCause
    anParameters.addAll(establishmentCauseParameter.toList())
    val plmnID = byteArrayOf(0x02, (0xf8).toByte(), 0x39)
    val plmnIDParameter = byteArrayOf(ANParametersType.ANParametersTypeSelectedPLMNID.value.toByte(), plmnID.size.toByte()) + plmnID
    anParameters.addAll(plmnIDParameter.toList())
    val nssai = mutableListOf<Byte>()
    val snssai1 = byteArrayOf(4, 1, 0x01, 0x02, 0x03)
    nssai.addAll(snssai1.toList())
    val snssai2 = byteArrayOf(4, 1, 0x11, 0x22, 0x33)
    nssai.addAll(snssai2.toList())
    val nssaiParameter = byteArrayOf(ANParametersType.ANParametersTypeRequestedNSSAI.value.toByte(), nssai.size.toByte()) + nssai.toByteArray()
    anParameters.addAll(nssaiParameter.toList())
    return anParameters.toByteArray()
}