package engine.ue


import config.Config
import engine.exchange.pkg.context.ChildSecurityAssociation
import engine.exchange.pkg.context.IkeSecurityAssociation
import engine.exchange.pkg.context.N3iwfUe
import engine.exchange.pkg.ike.handler.RandomNumberGenerator.generateRandomNumber
import engine.exchange.pkg.ike.handler.XFRMEncryptionAlgorithmType
import engine.exchange.pkg.ike.handler.XFRMIntegrityAlgorithmType
import engine.exchange.pkg.ike.handler.newPseudorandomFunction
import engine.exchange.pkg.ike.message.*
import engine.nas.*
import engine.ran.RanUeContext
import engine.util.*
import free5gc.nas.Message
import free5gc.nas.SecurityHeader
import free5gc.nas.SecurityHeader.Companion.SecurityHeaderTypeIntegrityProtectedAndCiphered
import free5gc.nas.nasMessage.CommInfoIE
import free5gc.nas.nasMessage.Epd5GSMobilityManagementMessage
import free5gc.openapi.models.Snssai
import go.net.*
import go.netlink.*
import org.slf4j.LoggerFactory
import java.net.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*
import javax.crypto.Mac
import kotlin.experimental.and


class UEnon3Gpp {
    private val log = LoggerFactory.getLogger(UEnon3Gpp::class.java)

    private var n3ue: N3iwfUe? = null
    private var ue: RanUeContext? = null
    private var n3iwfUDPAddrIP: InetAddress? = null
    private var n3iwfUDPAddrPort: String? = null
    private var udpConnection: DatagramSocket? = null
    private var tcpConnWithN3IWF: Socket? = null

    private fun initCommunicationElements(cfg: Config) {
        ue = createRanUEContext(cfg)
        /* new N3IWF Ue*/
        n3ue = createN3IWFUe()
        /* create N3IWF IKE connection */
        n3iwfUDPAddrIP = createN3IWFIKEConnectionIP(cfg)
        n3iwfUDPAddrPort = createN3IWFIKEConnectionPort(cfg)
        /* create Local UE UDP Listener */
        udpConnection = createUEUDPListener(cfg)
    }

    private fun ikeSaInit(cfg: Config): Quadruple<IKEMessage, Proposal, IkeSecurityAssociation, IKEPayloadContainer> {
        log.info("ikeSaInit")
        val (ikeMessage, proposal) = createIKEMessageSAInit()

        /* N3IWF Security Association request */
        val ikeSecurityAssociation: IkeSecurityAssociation =
            NetlinkUtils().createN3IWFSecurityAssociation(proposal, udpConnection!!, n3iwfUDPAddrIP!!, n3iwfUDPAddrPort!!, ikeMessage)
        n3ue!!.n3iwfIkeSecurityAssociation = ikeSecurityAssociation

        val ikePayload = IKEPayloadContainer()
        ikePayload.buildIdentificationInitiator(IdentificationType.ID_FQDN.value.toByte(), cfg.ue.iddata.toByteArray())

        return Quadruple(ikeMessage, proposal, ikeSecurityAssociation, ikePayload)
    }

    private fun ikeAuthRequest(ikeMessage: IKEMessage, proposalParam: Proposal, ikeSecurityAssociation: IkeSecurityAssociation, ikePayloadParam: IKEPayloadContainer): UByte {
        log.info("ikeAuthRequest")
        ikeMessage.payloads.reset()
        n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID++
        ikeMessage.buildIKEHeader(
            n3ue!!.n3iwfIkeSecurityAssociation!!.localSPI,
            n3ue!!.n3iwfIkeSecurityAssociation!!.remoteSPI,
            ExchangeType.IKE_AUTH.value.toUByte(),
            Flag.InitiatorBitCheck.value.toUByte(),
            n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID
        )

        val attributeType: UShort = AttributeType.AttributeTypeKeyLength.value.toUShort()
        val keyLength: UShort = 256u

        // Security Association
        val securityAssociation = ikePayloadParam.buildSecurityAssociation()

        // Proposal 1
        val inboundSPI = generateSPI(n3ue!!)
        val proposal = securityAssociation.proposals.buildProposal(1u, ProtocolType.TypeESP.value.toUByte(), inboundSPI)

        // ENCR
        proposal.encryptionAlgorithm.buildTransform(
            PayloadType.TypeEncryptionAlgorithm.value.toUByte(),
            EncryptionAlgorithm.ENCR_AES_CBC.value.toUShort(),
            attributeType,
            keyLength,
            ByteArray(0)
        )

        // INTEG
        proposal.integrityAlgorithm.buildTransform(
            PayloadType.TypeIntegrityAlgorithm.value.toUByte(),
            AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value.toUShort(),
            null,
            null,
            ByteArray(0)
        )

        // ESN
        proposal.extendedSequenceNumbers.buildTransform(
            PayloadType.TypeExtendedSequenceNumbers.value.toUByte(),
            ESNOption.ESN_NO.value.toUShort(),
            null,
            null,
            ByteArray(0)
        )

        // Traffic Selector
        val tsi = ikePayloadParam.buildTrafficSelectorInitiator()
        tsi.trafficSelectors.buildIndividualTrafficSelector(
            TS_IPV4_ADDR_RANGE, 0u, 0u, 65535u,
            byteArrayOf(0, 0, 0, 0), byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))

        val tsr = ikePayloadParam.buildTrafficSelectorResponder()
        tsr.trafficSelectors.buildIndividualTrafficSelector(
            TS_IPV4_ADDR_RANGE, 0u, 0u, 65535u,
            byteArrayOf(0, 0, 0, 0), byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))

        encryptProcedure(ikeSecurityAssociation, ikePayloadParam, ikeMessage)

        // Send to N3IWF
        val ikeMessageData = ikeMessage.encode()
        log.trace("ikeMessageData [${ikeMessageData.size}] " + ikeMessageData.toUByteArrayString())

        /*
        ikeMessageData[172] =
	        [0,26] ikeMessage.encode [27]
	        [27] = ikeMessageData.size [1]
	        [28, 31] = ikePayload.encode payloadData[4]
	        [32, 159] = encryptMessage [128]
	        [160,171] = encryptedData[12]
         */

        udpConnection?.send(DatagramPacket(ikeMessageData, ikeMessageData.size, n3iwfUDPAddrIP, n3iwfUDPAddrPort!!.toInt()))

        val auxInboundSPI = ByteBuffer.wrap(inboundSPI).order(ByteOrder.BIG_ENDIAN).int.toUInt()
        n3ue?.createHalfChildSA(n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID, auxInboundSPI)

        // Receive N3IWF reply
        val buffer = ByteArray(65535)
        val packet = DatagramPacket(buffer, buffer.size)
        udpConnection?.soTimeout = 5000
        try {
            udpConnection?.receive(packet)
        } catch (e: SocketTimeoutException) {
            throw e
        }
        ikeMessage.payloads.reset()
        ikeMessage.decode(Arrays.copyOfRange(buffer, 0, packet.length))

        val encryptedPayload = ikeMessage.payloads[0] as Encrypted
        val decryptedIKEPayload = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)

        var eapIdentifier: UByte = 0u
        for (ikePayload in decryptedIKEPayload) {
            when (ikePayload.type()) {
                IKEPayloadType.TypeIDr -> log.info("Get IDr")
                IKEPayloadType.TypeAUTH -> log.info("Get AUTH")
                IKEPayloadType.TypeCERT -> log.info("Get CERT")
                IKEPayloadType.TypeEAP -> {
                    eapIdentifier = (ikePayload as EAP).identifier
                    log.info("Get EAP")
                }
                else -> {}
            }
        }
        return eapIdentifier
    }


    private fun ikeAuthEapExchange(cfg: Config, ikeMessage: IKEMessage, ikePayload: IKEPayloadContainer, eapIdentifier: UByte, ikeSecurityAssociation: IkeSecurityAssociation) {
        log.info("ikeAuthEapExchange")

        /* 1º Registration Request */
        ikeMessage.payloads.reset()
        n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID++
        ikeMessage.buildIKEHeader(
            n3ue!!.n3iwfIkeSecurityAssociation!!.localSPI,
            n3ue!!.n3iwfIkeSecurityAssociation!!.remoteSPI,
            ExchangeType.IKE_AUTH.value.toUByte(),
            Flag.InitiatorBitCheck.value.toUByte(),
            n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID
        )
        ikePayload.reset()

        // EAP-5G vendor type data
        var eapVendorTypeData = ByteArray(2)
        eapVendorTypeData[0] = EAP5GType.EAP5GType5GNAS.value.toByte()

        // AN Parameters
        val anParameters = createEAP5GANParameters()
        val anParametersLength = ByteBuffer.allocate(2).putShort(anParameters.size.toShort()).array()

        eapVendorTypeData += anParametersLength
        eapVendorTypeData += anParameters

        // NAS
        val ueSecurityCapability = ue?.getUESecurityCapability()
        val mobileIdentity = createMobileIdentity(cfg)
        val registrationRequest = getRegistrationRequest(
            CommInfoIE.RegistrationType5GSInitialRegistration,
            mobileIdentity,
            null,
            ueSecurityCapability,
            null,
            null,
            null
        )

        var nasLength = ByteBuffer.allocate(2)
        nasLength.putShort(registrationRequest.size.toShort())

        eapVendorTypeData += nasLength.array()
        eapVendorTypeData += registrationRequest

        var eap = ikePayload.buildEAP(EAPCode.EAPCodeResponse.value, eapIdentifier)
        eap.eapTypeData.buildEAPExpanded(VendorID3GPP.toUInt(), VendorTypeEAP5G.toUInt(), eapVendorTypeData)

        encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)

        // Send to N3IWF
        var ikeMessageData = ikeMessage.encode()

        log.trace("Send to N3IWF ikeMessageData[${ikeMessageData.size}] = ${ikeMessageData.toUByteArrayString()}")
        // Envia 140
        udpConnection?.send(DatagramPacket(ikeMessageData, ikeMessageData.size, n3iwfUDPAddrIP, n3iwfUDPAddrPort!!.toInt()))

        // Receive N3IWF reply - Neste ponte é necessário o UE estar cadastrado no CORE com mesmo SUPI do arquivo de configuração, caso contrário teremos um erro de autenticação no AUSF
        var buffer = ByteArray(65535)
        var packet = DatagramPacket(buffer, buffer.size)
        udpConnection?.soTimeout = 7000
        udpConnection?.receive(packet)

        ikeMessage.payloads.reset()

        var receiveN3iwf = Arrays.copyOfRange(buffer, 0, packet.length)
        log.trace("Receive to N3IWF receiveN3iwf[${receiveN3iwf.size}] = ${receiveN3iwf.toUByteArrayString()}")
        // Recebe 124
        ikeMessage.decode(receiveN3iwf)

        var encryptedPayload = ikeMessage.payloads[0] as Encrypted
        var decryptedIKEPayload = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)

        var eapReq: EAP? = decryptedIKEPayload[0] as? EAP
        val eapExpanded: EAPExpanded? = eapReq!!.eapTypeData[0] as? EAPExpanded

        // Decode NAS - Authentication Request
        val nasData = eapExpanded!!.vendorData.copyOfRange(4, eapExpanded.vendorData.size)
        val decodedNAS = Message.newMessage()
        decodedNAS.plainNasDecode(nasData)

        // Calculate for RES*
        val rand = decodedNAS.gmmMessage!!.authenticationRequest!!.authenticationParameterRAND!!.getRANDValue()

        val resStat = ue!!.deriveRESstarAndSetKey(ue!!.authenticationSubs!!, rand.toByteArray(), "5G:mnc093.mcc208.3gppnetwork.org")
        log.trace("resStat[${resStat.size}] = ${resStat.toUByteArrayString()}")

        // send NAS Authentication Response
        var pdu = getAuthenticationResponse(resStat, "")
        log.trace("pdu[${pdu.size}] = ${pdu.toUByteArrayString()}")

        /* 2º Registration Request */
        ikeMessage.payloads.reset()
        n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID++
        ikeMessage.buildIKEHeader(
            n3ue!!.n3iwfIkeSecurityAssociation!!.localSPI,
            n3ue!!.n3iwfIkeSecurityAssociation!!.remoteSPI,
            ExchangeType.IKE_AUTH.value.toUByte(),
            Flag.InitiatorBitCheck.value.toUByte(),
            n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID
        )
        ikePayload.reset()

        // EAP-5G vendor type data
        eapVendorTypeData = ByteArray(4)
        eapVendorTypeData[0] = EAP5GType.EAP5GType5GNAS.value.toByte()

        // NAS - Authentication Response
        nasLength = ByteBuffer.allocate(2)
        nasLength.putShort(pdu.size.toShort())

        eapVendorTypeData += nasLength.array()
        eapVendorTypeData += pdu

        eap = ikePayload.buildEAP(EAPCode.EAPCodeResponse.value, eapReq.identifier)
        eap.eapTypeData.buildEAPExpanded(VendorID3GPP.toUInt(), VendorTypeEAP5G.toUInt(), eapVendorTypeData)

        log.trace("eapVendorTypeData[${eapVendorTypeData.size}] = ${eapVendorTypeData.toUByteArrayString()}")
        encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)

        // Send to N3IWF
        ikeMessageData = ikeMessage.encode()

        log.trace("Send to N3IWF ikeMessageData[${ikeMessageData.size}] = ${ikeMessageData.toUByteArrayString()}")
        // Envia 108
        udpConnection?.send(DatagramPacket(ikeMessageData, ikeMessageData.size, n3iwfUDPAddrIP, n3iwfUDPAddrPort!!.toInt()))

        // Receive N3IWF reply
        buffer = ByteArray(65535)
        packet = DatagramPacket(buffer, buffer.size)
        udpConnection?.soTimeout = 7000
        udpConnection?.receive(packet)

        ikeMessage.payloads.reset()

        receiveN3iwf = Arrays.copyOfRange(buffer, 0, packet.length)
        log.trace("Receive to N3IWF receiveN3iwf[${receiveN3iwf.size}] = ${receiveN3iwf.toUByteArrayString()}")
        // Recebe 108
        ikeMessage.decode(receiveN3iwf)

        encryptedPayload = ikeMessage.payloads[0] as Encrypted
        decryptedIKEPayload = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
        eapReq = decryptedIKEPayload[0] as? EAP

        //nasData = eapExpanded.vendorData.copyOfRange(4, eapExpanded.vendorData.size)

        // Send NAS Security Mode Complete Msg
        val registrationRequestWith5GMM = getRegistrationRequest(
            CommInfoIE.RegistrationType5GSInitialRegistration,
            mobileIdentity,
            null,
            ueSecurityCapability,
            ue?.get5GMMCapability(),
            null,
            null
        )
        pdu = getSecurityModeComplete(registrationRequestWith5GMM)
        pdu = encodeNasPduWithSecurity(
            ue,
            pdu,
            SecurityHeader.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext.toByte(),
            true,
            true
        )

        /*3 - requisição */
        ikeMessage.payloads.reset()
        n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID++
        ikeMessage.buildIKEHeader(
            n3ue!!.n3iwfIkeSecurityAssociation!!.localSPI,
            n3ue!!.n3iwfIkeSecurityAssociation!!.remoteSPI,
            ExchangeType.IKE_AUTH.value.toUByte(),
            Flag.InitiatorBitCheck.value.toUByte(),
            n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID
        )
        ikePayload.reset()

        // EAP-5G vendor type data
        eapVendorTypeData = ByteArray(4)
        eapVendorTypeData[0] = EAP5GType.EAP5GType5GNAS.value.toByte()

        // NAS - Authentication Response
        nasLength = ByteBuffer.allocate(2)
        nasLength.putShort(pdu.size.toShort())

        eapVendorTypeData += nasLength.array()
        eapVendorTypeData += pdu

        eap = ikePayload.buildEAP(EAPCode.EAPCodeResponse.value, eapReq!!.identifier)
        eap.eapTypeData.buildEAPExpanded(VendorID3GPP.toUInt(), VendorTypeEAP5G.toUInt(), eapVendorTypeData)

        encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)

        // Send to N3IWF
        ikeMessageData = ikeMessage.encode()

        log.trace("Send to N3IWF ikeMessageData[${ikeMessageData.size}] = ${ikeMessageData.toUByteArrayString()}")
        // Envia 140

        udpConnection?.send(DatagramPacket(ikeMessageData, ikeMessageData.size, n3iwfUDPAddrIP, n3iwfUDPAddrPort!!.toInt()))

        // Receive N3IWF reply
        buffer = ByteArray(65535)
        packet = DatagramPacket(buffer, buffer.size)
        udpConnection?.soTimeout = 10000
        udpConnection?.receive(packet)

        receiveN3iwf = Arrays.copyOfRange(buffer, 0, packet.length)
        log.trace("Receive to N3IWF receiveN3iwf[${receiveN3iwf.size}] = ${receiveN3iwf.toUByteArrayString()}")
        // Recebe 76

        ikeMessage.payloads.reset()
        ikeMessage.decode(Arrays.copyOfRange(buffer, 0, packet.length))

        encryptedPayload = ikeMessage.payloads[0] as Encrypted
        decryptedIKEPayload = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)

        eapReq = decryptedIKEPayload[0] as? EAP

        if (eapReq!!.code != EAPCode.EAPCodeSuccess.value) {
            log.warn("Check UE sequenceNumber value in config.yaml with the respective value in MONGO db.subscriptionData.authenticationData.authenticationSubscription.")
            log.error("Not Success! Eap Req Code: ${eapReq.code}")
            throw Exception("Not Success")
        }
    }

    private fun ikeAuth(cfg: Config, ikeMessage: IKEMessage, ikePayloadParam: IKEPayloadContainer, ikeSecurityAssociation: IkeSecurityAssociation): Pair<IPNet, TCPAddr> {
        ikeMessage.payloads.reset()
        n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID++
        ikeMessage.buildIKEHeader(
            n3ue!!.n3iwfIkeSecurityAssociation!!.localSPI,
            n3ue!!.n3iwfIkeSecurityAssociation!!.remoteSPI,
            ExchangeType.IKE_AUTH.value.toUByte(),
            Flag.InitiatorBitCheck.value.toUByte(),
            n3ue!!.n3iwfIkeSecurityAssociation!!.initiatorMessageID
        )
        ikePayloadParam.reset()

        // Authentication
        ikePayloadParam.buildAuthentication(SignatureType.SharedKeyMesageIntegrityCode.value.toByte(), byteArrayOf(1, 2, 3))

        // Configuration Request
        val configurationRequest = ikePayloadParam.buildConfiguration(ConfigurationMessageType.CFG_REQUEST.value.toByte())
        configurationRequest.configurationAttribute.buildConfigurationAttribute(ConfigurationAttributeType.INTERNAL_IP4_ADDRESS.value.toUShort(), ByteArray(0))

        encryptProcedure(ikeSecurityAssociation, ikePayloadParam, ikeMessage)

        // Send to N3IWF
        val ikeMessageData = ikeMessage.encode()

        log.trace("Send to N3IWF ikeMessageData[${ikeMessageData.size}] = ${ikeMessageData.toUByteArrayString()}")
        // Envia 92

        udpConnection?.send(DatagramPacket(ikeMessageData, ikeMessageData.size, n3iwfUDPAddrIP, n3iwfUDPAddrPort!!.toInt()))

        // Receive N3IWF reply
        val buffer = ByteArray(65535)
        val packet = DatagramPacket(buffer, buffer.size)
        udpConnection?.soTimeout = 16000
        try {
            udpConnection?.receive(packet)
        } catch (e: SocketTimeoutException) {
            throw e
        }

        ikeMessage.payloads.reset()

        val receiveN3iwf = Arrays.copyOfRange(buffer, 0, packet.length)
        log.trace("Receive to N3IWF receiveN3iwf[${receiveN3iwf.size}] = ${receiveN3iwf.toUByteArrayString()}")
        // Recebe 236
        ikeMessage.decode(receiveN3iwf)

        val encryptedPayload = ikeMessage.payloads[0] as Encrypted
        val decryptedIKEPayload = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)

        // AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
        var responseSecurityAssociation: SecurityAssociation?
        var responseTrafficSelectorInitiator: TrafficSelectorInitiator? = null
        var responseTrafficSelectorResponder: TrafficSelectorResponder? = null
        var responseConfiguration: Configuration?

        val n3iwfNASAddr = TCPAddr()
        val ueAddr = IPNet()

        for (ikePayload in decryptedIKEPayload) {
            when (ikePayload.type()) {
                IKEPayloadType.TypeAUTH -> log.info("Get Authentication from N3IWF")
                IKEPayloadType.TypeSA -> {
                    responseSecurityAssociation = ikePayload as SecurityAssociation
                    n3ue!!.n3iwfIkeSecurityAssociation!!.ikeAuthResponseSA = responseSecurityAssociation
                }
                IKEPayloadType.TypeTSi -> responseTrafficSelectorInitiator = ikePayload as TrafficSelectorInitiator
                IKEPayloadType.TypeTSr -> responseTrafficSelectorResponder = ikePayload as TrafficSelectorResponder
                IKEPayloadType.TypeN -> {
                    val notification = ikePayload as Notification
                    if (notification.notifyMessageType.toInt() == Vendor3GPPNotifyTypeNAS_IP4_ADDRESS.toInt()) {
                        n3iwfNASAddr.IP = n3iwfNASAddr.IP.iPv4(notification.notificationData[0], notification.notificationData[1], notification.notificationData[2], notification.notificationData[3])
                    }
                    if (notification.notifyMessageType.toInt() == Vendor3GPPNotifyTypeNAS_TCP_PORT.toInt()) {
                        val port = ByteBuffer.wrap(notification.notificationData).short.toInt()
                        n3iwfNASAddr.port = port
                    }
                }
                IKEPayloadType.TypeCP -> {
                    responseConfiguration = ikePayload as Configuration
                    if (responseConfiguration.configurationType.toInt() == ConfigurationMessageType.CFG_REPLY.value.toInt()) {
                        for (configAttr in responseConfiguration.configurationAttribute.attributes) {
                            when (configAttr.type) {
                                ConfigurationAttributeType.INTERNAL_IP4_ADDRESS.value.toUShort() ->
                                    ueAddr.ip = IP.newIP(configAttr.value)
                                ConfigurationAttributeType.INTERNAL_IP4_NETMASK.value.toUShort() ->
                                    ueAddr.mask = IPMask.newIPMask(configAttr.value)
                            }
                        }
                    }
                }
                else -> {}
            }
        }

        val outboundSPI: UInt = ByteBuffer.wrap(n3ue!!.n3iwfIkeSecurityAssociation!!.ikeAuthResponseSA!!.proposals[0].spi).order(ByteOrder.BIG_ENDIAN).int.toUInt()
        val childSecurityAssociationContext = n3ue?.completeChildSA(
            0x01u,
            outboundSPI,
            n3ue!!.n3iwfIkeSecurityAssociation!!.ikeAuthResponseSA
        )
        if (childSecurityAssociationContext == null) {
            throw Exception("Create child security association context failed")
        }

        parseIPAddressInformationToChildSecurityAssociation(
            cfg,
            childSecurityAssociationContext,
            responseTrafficSelectorInitiator!!.trafficSelectors[0],
            responseTrafficSelectorResponder!!.trafficSelectors[0]
        )

        // Select TCP traffic
        childSecurityAssociationContext.selectedIpProtocol = Proto.IPPROTO_TCP.value.toUByte()
        generateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContext)

        // Aplly XFRM rules
        applyXFRMRule(true, cfg, childSecurityAssociationContext)

        return Pair(ueAddr, n3iwfNASAddr)
    }

    private fun nasRegistration(cfg: Config, ueAddr: IPNet, n3iwfNasAddrIP: TCPAddr) {
        val ipSecInterfaceName = cfg.ue.ipSecInterfaceName

        // Verifica se a interface de rede existe e está up
        if (!NetlinkUtils().isNetworkInterfaceAvailable(ipSecInterfaceName)) {
            throw Exception("No link named ${cfg.ue.ipSecInterfaceName}")
        }

        // Adiciona o endereço IP à interface de rede
        NetlinkUtils().addIpAddressToNetworkInterface(ipSecInterfaceName, ueAddr.string(), "10.0.0.255")

        val localTCPAddr = InetSocketAddress(ueAddr.ip.string(), 0)
        val n3iwfNASAddr = InetSocketAddress(n3iwfNasAddrIP.IP.string(), n3iwfNasAddrIP.port)

        tcpConnWithN3IWF = Socket()
        tcpConnWithN3IWF!!.bind(localTCPAddr)  // associa o socket ao endereço local
        tcpConnWithN3IWF!!.connect(n3iwfNASAddr) // conecta ao endereço remoto

        val nasMsg = ByteArray(65535)
        val bytesRead = tcpConnWithN3IWF!!.getInputStream().read(nasMsg)

        var pdu = getRegistrationComplete(null)
        pdu = encodeNasPduInEnvelopeWithSecurity(ue!!, pdu, SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)

        tcpConnWithN3IWF!!.getOutputStream().write(pdu)
        Thread.sleep(1000)
    }


    private fun uePDUSessionSetup(cfg: Config, ikeMessage: IKEMessage, ikePayload: IKEPayloadContainer, ikeSecurityAssociation: IkeSecurityAssociation): Pair<PDUQoSInfo?, IP> {
        val sNssai = Snssai(cfg.ue.snssai.sst, cfg.ue.snssai.sd)

        val pdu = getUlNasTransportPduSessionEstablishmentRequest(
            cfg.ue.pdusessionid.toUByte(), CommInfoIE.ULNASTransportRequestTypeInitialRequest, cfg.ue.dnnstring, sNssai)

        val encodedPdu = encodeNasPduInEnvelopeWithSecurity(ue!!, pdu, SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)

        tcpConnWithN3IWF!!.getOutputStream().write(encodedPdu)

        // Receive N3IWF reply
        val buffer = ByteArray(65535)
        val udpPacket = DatagramPacket(buffer, buffer.size)
        udpConnection!!.receive(udpPacket)
        
        val n = udpPacket.length
        val receivedData = udpPacket.data.copyOf(n)
        // Recebe 444

        ikeMessage.payloads.reset()
        ikeMessage.decode(receivedData)
        val encryptedPayload = ikeMessage.payloads[0] as? Encrypted
        if (encryptedPayload == null) {
            log.error("Received packet is not an encrypted payload")
            throw Exception("Received packet is not an encrypted payload")
        }
        val decryptedIKEPayload = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
        var responseSecurityAssociation: SecurityAssociation? = null
        var responseTrafficSelectorInitiator: TrafficSelectorInitiator? = null
        var responseTrafficSelectorResponder: TrafficSelectorResponder? = null
        var qosInfo: PDUQoSInfo? = null
        var upIPAddr: IP? = null
        var outboundSPI = ByteBuffer.wrap(n3ue!!.n3iwfIkeSecurityAssociation!!.ikeAuthResponseSA!!.proposals[0].spi).order(ByteOrder.BIG_ENDIAN).int
        for (ikePayloadType in decryptedIKEPayload) {
            when (ikePayloadType.type()) {
                IKEPayloadType.TypeSA -> {
                    responseSecurityAssociation = ikePayloadType as SecurityAssociation
                    outboundSPI = ByteBuffer.wrap(responseSecurityAssociation.proposals[0].spi).order(ByteOrder.BIG_ENDIAN).int
                }
                IKEPayloadType.TypeTSi -> {
                    responseTrafficSelectorInitiator = ikePayloadType as TrafficSelectorInitiator
                }
                IKEPayloadType.TypeTSr -> {
                    responseTrafficSelectorResponder = ikePayloadType as TrafficSelectorResponder
                }
                IKEPayloadType.TypeN -> {
                    val notification = ikePayloadType as Notification
                    if (notification.notifyMessageType.toInt() == Vendor3GPPNotifyType5G_QOS_INFO.toInt()) {
                        val info = parse5GQoSInfoNotify(notification)
                        qosInfo = info
                        if (qosInfo.isDSCPSpecified) {
                            log.info("DSCP is specified but test not support")
                        }
                    }
                    if (notification.notifyMessageType.toInt() == Vendor3GPPNotifyTypeUP_IP4_ADDRESS.toInt()) {
                        upIPAddr = IP.newIP(notification.notificationData.copyOfRange(0, 4))
                    }
                }
                IKEPayloadType.TypeNiNr -> {
                    val responseNonce = ikePayloadType as Nonce
                    ikeSecurityAssociation.concatenatedNonce = responseNonce.nonceData
                }
                else -> {}
            }
        }
        ikeMessage.payloads.reset()
        ikeMessage.buildIKEHeader(
            ikeMessage.initiatorSPI,
            ikeMessage.responderSPI,
            ExchangeType.CREATE_CHILD_SA.value.toUByte(),
            (Flag.ResponseBitCheck.value.toInt() or Flag.InitiatorBitCheck.value.toInt()).toUByte(),
            n3ue!!.n3iwfIkeSecurityAssociation!!.responderMessageID
        )

        ikePayload.reset()

        // SA
        val inboundSPI = generateSPI(n3ue!!)
        responseSecurityAssociation!!.proposals[0].spi = inboundSPI
        ikePayload.add(responseSecurityAssociation)

        // TSi
        ikePayload.add(responseTrafficSelectorInitiator!!)

        // TSr
        ikePayload.add(responseTrafficSelectorResponder!!)

        // Nonce
        val localNonce = generateRandomNumber().toByteArray()
        ikeSecurityAssociation.concatenatedNonce += localNonce
        ikePayload.buildNonce(localNonce)
        encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)

        val ikeMessageData = ikeMessage.encode()
        // Envia 428

        // Send to N3IWF
        udpConnection!!.send(DatagramPacket(ikeMessageData, ikeMessageData.size, n3iwfUDPAddrIP, n3iwfUDPAddrPort!!.toInt()))

        n3ue!!.createHalfChildSA(
            n3ue!!.n3iwfIkeSecurityAssociation!!.responderMessageID,
            ByteBuffer.wrap(inboundSPI).order(ByteOrder.BIG_ENDIAN).int.toUInt()
        )

        val childSecurityAssociationContextUserPlane = n3ue!!.completeChildSA(
            n3ue!!.n3iwfIkeSecurityAssociation!!.responderMessageID,
            outboundSPI.toUInt(),
            responseSecurityAssociation
        )

        if (childSecurityAssociationContextUserPlane == null) {
            log.error("Create child security association context failed")
            throw Exception("Create child security association context failed")
        }
        parseIPAddressInformationToChildSecurityAssociation(
            cfg,
            childSecurityAssociationContextUserPlane,
            responseTrafficSelectorResponder.trafficSelectors[0],
            responseTrafficSelectorInitiator.trafficSelectors[0]
        )

        // Select GRE traffic
        childSecurityAssociationContextUserPlane.selectedIpProtocol = Proto.IPPROTO_GRE.value.toUByte()
        generateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContextUserPlane)
        applyXFRMRule(false, cfg, childSecurityAssociationContextUserPlane)
        return Pair(qosInfo, upIPAddr!!)
    }


    private fun greTunSetup(cfg: Config, qosInfo: PDUQoSInfo?, upIPAddr: IP, ueAddr: IPNet) {
        var greKeyField = 0u

        qosInfo?.let {
            greKeyField = ((it.qfiList[0].toUInt() and 0x3FU) shl 24)
        }

        println("............................")
        println("")
        print("ueAddr.IP: ")
        println(ueAddr.ip.string())
        print("upIPAddr: ")
        println(upIPAddr.string())
        println("")

        try {
            // COMANDO GO
            // netlink.LinkAdd(newGRETunnel)
            NetlinkUtils().addIpLinkGRE(cfg.ue.linkGRE.name, ueAddr.ip.string(), upIPAddr.string(), greKeyField.toLong(), greKeyField.toLong())
        } catch (e: Exception) {
            throw Exception("GRETunSetup Failed to add GRE tunnel: ${e.message}")
        }

        EnvironmentSetting().configMTUGreTun(cfg)


        // COMANDO GO
        // netlink.AddrAdd(linkGRE, linkGREAddr)
        NetlinkUtils().addIpAddressToNetworkInterface(cfg.ue.linkGRE.name, "60.60.0.1/32", "")

        // COMANDO GO
        // Set GRE interface up
        // netlink.LinkSetUp(linkGRE)
        NetlinkUtils().upLinkInterface(cfg.ue.linkGRE.name)

        // COMANDO GO
        // netlink.RouteAdd(upRoute)
        NetlinkUtils().addIpRoute(cfg.ue.ipSecInterfaceName, ueAddr.ip.string(), "10.0.0.0/24", 1)
    }


    fun ueNon3GPPConnection(cfg: Config) {
        val environmentSetting = EnvironmentSetting()
        environmentSetting.cleanEnvironment(cfg)

        /* create communitcaion elements */
        initCommunicationElements(cfg)

        /* ---- 1º IKE SA INIT --- */
        val (ikeMessage, proposal, ikeSecurityAssociation, ikePayload) = ikeSaInit(cfg)

        /* -- 2º IKE AUTH Request --- */
        val eapIdentifier = ikeAuthRequest(ikeMessage, proposal, ikeSecurityAssociation, ikePayload)

        /* -- 3º IKE_AUTH - EAP exchange | 3 Requisições -- refatorar --- */
        ikeAuthEapExchange(cfg, ikeMessage, ikePayload, eapIdentifier, ikeSecurityAssociation)

        /* -- 4º IKE_AUTH - Authentication --- */
        val (ueAddr, n3iwfNASAddr) = ikeAuth(cfg, ikeMessage, ikePayload, ikeSecurityAssociation)

        /* -- 5º Stablish TCP communication + NAS Registration --- */
        nasRegistration(cfg, ueAddr, n3iwfNASAddr)

        /* -- 6º UE request PDU session setup --- */
        val (qosInfo, upIPAddr) = uePDUSessionSetup(cfg, ikeMessage, ikePayload, ikeSecurityAssociation)

        /* -- 7º Data Communication Setup  --- */
        greTunSetup(cfg, qosInfo, upIPAddr, ueAddr)

        println("")
        print("UE-non3GPP is ready! ")
        print("Try ping -I " + cfg.ue.linkGRE.name + " 8.8.8.8 ")
        println("")
        println("............................")
        while (true) {
            val downGreTunInterface = "ping -I " + cfg.ue.linkGRE.name + " 8.8.8.8"
            environmentSetting.executeCommand(downGreTunInterface)
            Thread.sleep(5000)
        }
    }

    private fun parse5GQoSInfoNotify(n: Notification): PDUQoSInfo {
        val info = PDUQoSInfo()
        var offset = 0
        val data = n.notificationData
        val dataLen = data[0].toInt()
        info.pduSessionID = data[1].toUByte()
        val qfiListLen = data[2].toInt()
        offset += (3 + qfiListLen)

        if (offset > dataLen) {
            throw IllegalArgumentException("parse5GQoSInfoNotify err: Length and content of 5G-QoS-Info-Notify mismatch")
        }

        info.qfiList = data.copyOfRange(3, 3 + qfiListLen)
        info.isDefault = (data[offset] and NotifyType5G_QOS_INFOBitDCSICheck) > 0
        info.isDSCPSpecified = (data[offset] and NotifyType5G_QOS_INFOBitDSCPICheck) > 0
        return info
    }

    private fun encodeNasPduInEnvelopeWithSecurity(ue: RanUeContext, pdu: ByteArray, auxSecurityHeaderType: UByte, securityContextAvailable: Boolean, newSecurityContext: Boolean): ByteArray {
        val m = Message.newMessage()
        m.plainNasDecode(pdu)

        m.securityHeader = SecurityHeader().apply {
            protocolDiscriminator = Epd5GSMobilityManagementMessage
            securityHeaderType = auxSecurityHeaderType
        }
        return nasEnvelopeEncode(ue, m, securityContextAvailable, newSecurityContext)
    }

    private fun nasEnvelopeEncode(ue: RanUeContext?, msg: Message?, securityContextAvailable: Boolean, newSecurityContext: Boolean): ByteArray {
        if (ue == null) {
            throw Exception("amfUe is null")
        }
        if (msg == null) {
            throw Exception("Nas Message is empty")
        }
        if (!securityContextAvailable) {
            val tmpNasPdu = msg.plainNasEncode()
            return encapNasMsgToEnvelope(tmpNasPdu!!)
        } else {
            if (newSecurityContext) {
                ue.ulCount.set(0u, 0u)
                ue.dlCount.set(0u, 0u)
            }
            val sequenceNumber = ue.ulCount.sqn()
            val payload = msg.plainNasEncode()
            log.trace("payload[${payload!!.size}] = ${payload.toUByteArrayString()}")

            try {
                free5gc.nas.security.nasEncrypt(
                    ue.cipheringAlg,
                    ue.knasEnc.toByteArray(),
                    ue.ulCount.get(),
                    ue.getBearerType().toUByte(),
                    free5gc.nas.security.DirectionUplink,
                    payload
                )

            } catch (err: Exception) {
                throw Exception("Failed to encrypt NAS message")
            }

            val payloadWithSeqNum = byteArrayOf(sequenceNumber.toByte()) + payload
            val mac32 = free5gc.nas.security.nasMacCalculate(
                ue.integrityAlg,
                ue.knasInt,
                ue.ulCount.get(),
                ue.getBearerType().toUByte(),
                free5gc.nas.security.DirectionUplink,
                payloadWithSeqNum)

            val payloadWithMac = mac32 + payloadWithSeqNum
            log.trace("payloadWithMac[${payloadWithMac.size}] = ${payloadWithMac.toUByteArrayString()}")

            val msgSecurityHeader = byteArrayOf(msg.securityHeader.protocolDiscriminator.toByte(), msg.securityHeader.securityHeaderType.toByte())
            log.trace("msgSecurityHeader[${msgSecurityHeader.size}] = ${msgSecurityHeader.toUByteArrayString()}")

            val payloadWithHeader = msgSecurityHeader + payloadWithMac
            log.trace("payloadWithHeader[${payloadWithHeader.size}] = ${payloadWithHeader.toUByteArrayString()}")

            ue.ulCount.addOne()
            return encapNasMsgToEnvelope(payloadWithHeader)
        }
    }

    private fun encapNasMsgToEnvelope(nasPDU: ByteArray): ByteArray {
        // According to TS 24.502 8.2.4,
        // in order to transport a NAS message over the non-3GPP access between the UE and the N3IWF,
        // the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
        // According to TS 24.502 9.4,
        // a NAS message envelope = Length | NAS Message
        val nasEnv = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(nasPDU.size.toShort()).array() + nasPDU
        return nasEnv
    }

    
    // Build XFRM information data structure for incoming traffic.
    private fun applyXFRMRule(ueIsInitiator: Boolean, cfg: Config, childSecurityAssociation: ChildSecurityAssociation) {
        // Mark
        val mark = XfrmMark().apply {
            value = cfg.ue.ipSecInterfaceMark.toUInt()
        }

        // Direction: N3IWF -> UE
        // State
        val xfrmEncryptionAlgorithm: XfrmStateAlgo
        var xfrmIntegrityAlgorithm = XfrmStateAlgo()
        if (ueIsInitiator) {
            xfrmEncryptionAlgorithm = XfrmStateAlgo().apply {
                name = XFRMEncryptionAlgorithmType.fromValue(childSecurityAssociation.encryptionAlgorithm.toUInt()).toString()
                key = childSecurityAssociation.responderToInitiatorEncryptionKey
            }
            if (childSecurityAssociation.integrityAlgorithm.toInt() != 0) {
                xfrmIntegrityAlgorithm = XfrmStateAlgo().apply {
                    name = XFRMIntegrityAlgorithmType.fromValue(childSecurityAssociation.integrityAlgorithm.toUInt()).toString()
                    key = childSecurityAssociation.responderToInitiatorIntegrityKey
                }
            }
        } else {
            xfrmEncryptionAlgorithm = XfrmStateAlgo().apply {
                name = XFRMEncryptionAlgorithmType.fromValue(childSecurityAssociation.encryptionAlgorithm.toUInt()).toString()
                key = childSecurityAssociation.initiatorToResponderEncryptionKey
            }
            if (childSecurityAssociation.integrityAlgorithm.toInt() != 0) {
                xfrmIntegrityAlgorithm = XfrmStateAlgo().apply {
                    name = XFRMIntegrityAlgorithmType.fromValue(childSecurityAssociation.integrityAlgorithm.toUInt()).toString()
                    key = childSecurityAssociation.initiatorToResponderIntegrityKey
                }
            }
        }

        // State
        val xfrmState = XfrmState().apply {
            src = childSecurityAssociation.peerPublicIpAddr!!
            dst = childSecurityAssociation.localPublicIpAddr!!
            proto = Proto.XFRM_PROTO_ESP
            mode = Mode.XFRM_MODE_TUNNEL
            this.spi = childSecurityAssociation.inboundSpi
            this.mark = mark
            auth = xfrmIntegrityAlgorithm
            crypt = xfrmEncryptionAlgorithm
            esn = childSecurityAssociation.esn
        }
        try {
            // Commit xfrm state to netlink
            xfrmStateAdd(xfrmState)
        } catch (err: Exception) {
            throw Exception("Set XFRM state rule failed: ${err.message}")
        }

        // Policy
        val xfrmPolicyTemplate = XfrmPolicyTmpl().apply {
            src = xfrmState.src
            dst = xfrmState.dst
            proto = xfrmState.proto
            mode = xfrmState.mode
            spi = xfrmState.spi
        }

        val xfrmPolicy = XfrmPolicy().apply {
            src = childSecurityAssociation.trafficSelectorRemote!!
            dst = childSecurityAssociation.trafficSelectorLocal!!
            proto = Proto.fromValue(childSecurityAssociation.selectedIpProtocol.toInt())!!
            dir = Dir.XFRM_DIR_IN
            this.mark = mark
            tmpls = listOf(xfrmPolicyTemplate)
        }

        try {
            // Commit xfrm policy to netlink
            xfrmPolicyAdd(xfrmPolicy)
        } catch (err: Exception) {
            throw Exception("Set XFRM policy rule failed: ${err.message}")
        }

        // Direction: UE -> N3IWF
        // State
        if (ueIsInitiator) {
            xfrmEncryptionAlgorithm.key = childSecurityAssociation.initiatorToResponderEncryptionKey
            if (childSecurityAssociation.integrityAlgorithm.toInt() != 0) {
                xfrmIntegrityAlgorithm.key = childSecurityAssociation.initiatorToResponderIntegrityKey
            }
        } else {
            xfrmEncryptionAlgorithm.key = childSecurityAssociation.responderToInitiatorEncryptionKey
            if (childSecurityAssociation.integrityAlgorithm.toInt() != 0) {
                xfrmIntegrityAlgorithm.key = childSecurityAssociation.responderToInitiatorIntegrityKey
            }
        }

        // State
        xfrmState.src = childSecurityAssociation.localPublicIpAddr!!
        xfrmState.dst = childSecurityAssociation.peerPublicIpAddr!!
        xfrmState.spi = childSecurityAssociation.outboundSpi
        
        try {
            // Commit xfrm state to netlink
            xfrmStateAdd(xfrmState)
        } catch (err: Exception) {
            throw Exception("Set XFRM state rule failed: ${err.message}")
        }

        // Policy
        xfrmPolicyTemplate.src = xfrmState.src
        xfrmPolicyTemplate.dst = xfrmState.dst
        xfrmPolicyTemplate.spi = childSecurityAssociation.outboundSpi
        xfrmPolicy.src = childSecurityAssociation.trafficSelectorLocal!!
        xfrmPolicy.dst = childSecurityAssociation.trafficSelectorRemote!!
        xfrmPolicy.dir = Dir.XFRM_DIR_OUT
        xfrmPolicy.tmpls = listOf(xfrmPolicyTemplate)
        
        try {
            // Commit xfrm policy to netlink
            xfrmPolicyAdd(xfrmPolicy)
        } catch (err: Exception) {
            throw Exception("Set XFRM policy rule failed: ${err.message}")
        }
    }

    private fun generateKeyForChildSA(ikeSecurityAssociation: IkeSecurityAssociation, childSecurityAssociation: ChildSecurityAssociation) {
        // Transforms
        val transformPseudorandomFunction = ikeSecurityAssociation.pseudorandomFunction
        val transformIntegrityAlgorithmForIPSec = ikeSecurityAssociation.ikeAuthResponseSA!!.proposals[0].integrityAlgorithm.transforms[0]

        // Get key length for encryption and integrity key for IPSec
        val lengthEncryptionKeyIPSec = 32
        val lengthIntegrityKeyIPSec = if (transformIntegrityAlgorithmForIPSec != null) 20 else 0
        val totalKeyLength = (lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec) * 2

        // Generate key for child security association as specified in RFC 7296 section 2.17
        val seed = ikeSecurityAssociation.concatenatedNonce
        var pseudorandomFunction: Mac

        var keyStream = byteArrayOf()
        var generatedKeyBlock = byteArrayOf()
        var index: Byte = 1

        while (keyStream.size < totalKeyLength) {
            pseudorandomFunction = newPseudorandomFunction(ikeSecurityAssociation.skD, transformPseudorandomFunction!!.transformID)
            pseudorandomFunction.update(appendArrays(generatedKeyBlock, seed, byteArrayOf(index)))
            generatedKeyBlock = pseudorandomFunction.doFinal()
            keyStream += generatedKeyBlock
            index++
        }
        childSecurityAssociation.initiatorToResponderEncryptionKey += keyStream.copyOfRange(0, lengthEncryptionKeyIPSec)
        keyStream = keyStream.copyOfRange(lengthEncryptionKeyIPSec, keyStream.size)

        childSecurityAssociation.initiatorToResponderIntegrityKey += keyStream.copyOfRange(0, lengthIntegrityKeyIPSec)
        keyStream = keyStream.copyOfRange(lengthIntegrityKeyIPSec, keyStream.size)

        childSecurityAssociation.responderToInitiatorEncryptionKey += keyStream.copyOfRange(0, lengthEncryptionKeyIPSec)
        keyStream = keyStream.copyOfRange(lengthEncryptionKeyIPSec, keyStream.size)

        childSecurityAssociation.responderToInitiatorIntegrityKey += keyStream.copyOfRange(0, lengthIntegrityKeyIPSec)
    }

    private fun appendArrays(vararg arrays: ByteArray): ByteArray {
        val totalLength = arrays.sumOf { it.size }
        val result = ByteArray(totalLength)
        var currentIndex = 0

        for (array in arrays) {
            array.copyInto(result, currentIndex)
            currentIndex += array.size
        }
        return result
    }

    private fun parseIPAddressInformationToChildSecurityAssociation(
        cfg: Config,
        childSecurityAssociation: ChildSecurityAssociation?,
        trafficSelectorLocal: IndividualTrafficSelector?,
        trafficSelectorRemote: IndividualTrafficSelector?
    ) {
        if (childSecurityAssociation == null) {
            throw Exception("childSecurityAssociation is nil")
        }
        childSecurityAssociation.peerPublicIpAddr = IP.newIP(InetAddress.getByName(cfg.n3iwfInfo.ikeBindAddress).address)
        childSecurityAssociation.localPublicIpAddr = IP.newIP(InetAddress.getByName(cfg.ue.localPublicIPAddr).address)

        childSecurityAssociation.trafficSelectorLocal = IPNet.newIPNet(
            IP.newIP(trafficSelectorLocal!!.startAddress),
            IPMask.newIPMask(byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))
        )
        childSecurityAssociation.trafficSelectorRemote = IPNet.newIPNet(
            IP.newIP(trafficSelectorRemote!!.startAddress),
            IPMask.newIPMask(byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))
        )
    }

    private fun generateSPI(n3ue: N3iwfUe): ByteArray {
        val spi: UInt
        val spiByte = ByteArray(4)
        while (true) {
            val randomUint64 = generateRandomNumber().toLong().toULong()
            if (!n3ue.n3iwfChildSecurityAssociation.containsKey(randomUint64)) {
                spi = randomUint64.toUInt()
                ByteBuffer.wrap(spiByte).putInt(spi.toInt())
                break
            }
        }
        return spiByte
    }
}

class PDUQoSInfo {
    var pduSessionID: UByte = 0u
    var qfiList: ByteArray = ByteArray(0)
    var isDefault: Boolean = false
    var isDSCPSpecified: Boolean = false
    var dscp: UByte = 0u
}