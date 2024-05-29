package engine.exchange.pkg.ike.message

import engine.util.toShort
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.nio.ByteOrder

private val log = LoggerFactory.getLogger("Message")

class Proposal {
    var proposalNumber: UByte = 0u
    var protocolID: UByte = 0u
    var spi: ByteArray = ByteArray(0)
    var encryptionAlgorithm = TransformContainer()
    var pseudorandomFunction = TransformContainer()
    var integrityAlgorithm = TransformContainer()
    var diffieHellmanGroup = TransformContainer()
    var extendedSequenceNumbers = TransformContainer()
}

class ProposalContainer : ArrayList<Proposal>() {
    fun reset() {
        clear()
    }

    fun buildProposal(proposalNumber: UByte, protocolID: UByte, spi: ByteArray): Proposal {
        val proposal = Proposal()
        proposal.proposalNumber = proposalNumber
        proposal.protocolID = protocolID
        proposal.spi = spi.copyOf()
        proposal.encryptionAlgorithm = TransformContainer()
        proposal.pseudorandomFunction = TransformContainer()
        proposal.integrityAlgorithm = TransformContainer()
        proposal.diffieHellmanGroup = TransformContainer()
        proposal.extendedSequenceNumbers = TransformContainer()
        add(proposal)
        return proposal
    }
}


class Transform {
    var transformType: UByte = 0u
    var transformID: UShort = 0u
    var attributePresent: Boolean = false
    var attributeFormat: UByte = 0u
    var attributeType: UShort = 0u
    var attributeValue: UShort = 0u
    var variableLengthAttributeValue: ByteArray = ByteArray(0)
}

class TransformContainer {
    var transforms: MutableList<Transform> = mutableListOf()

    fun reset() {
        transforms.clear()
    }

    fun buildTransform(
        transformType: UByte,
        transformID: UShort,
        attributeType: UShort?,
        attributeValue: UShort?,
        variableLengthAttributeValue: ByteArray
    ) {
        val transform = Transform()
        transform.transformType = transformType
        transform.transformID = transformID
        transform.attributePresent = attributeType != null

        if (attributeType != null) {
            transform.attributeType = attributeType
            if (attributeValue != null) {
                transform.attributeFormat = AttributeFormat.AttributeFormatUseTV.value.toUByte()
                transform.attributeValue = attributeValue
            } else if (variableLengthAttributeValue.isNotEmpty()) {
                transform.attributeFormat = AttributeFormat.AttributeFormatUseTLV.value.toUByte()
                transform.variableLengthAttributeValue = variableLengthAttributeValue
            } else {
                return
            }
        }
        transforms.add(transform)
    }
}




class IKEPayloadContainer : ArrayList<IKEPayload>() {
    companion object {
        val log: Logger = LoggerFactory.getLogger(IKEPayloadContainer::class.java)
    }

    fun encode(): ByteArray {
        log.info("Encoding IKE payloads")
        var ikeMessagePayloadData = ByteArray(0)
        for (index in indices) {
            val payload = this[index]
            var payloadData = ByteArray(4)
            if (index + 1 < size) {
                payloadData[0] = this[index + 1].type().value.toByte()
            } else {
                if (payload.type() == IKEPayloadType.TypeSK) {
                    payloadData[0] = (payload as Encrypted).nextPayload.toByte()
                } else {
                    payloadData[0] = IKEPayloadType.NoNext.value.toByte()
                }
            }
            val data = payload.marshal()
            payloadData += data
            val payloadLength = payloadData.size.toShort()
            ByteBuffer.wrap(payloadData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(payloadLength)  // pos 2 e 3

            log.trace("payloadData [${payloadData.size}] = ${payloadData.toUByteArray().contentToString()}")
            ikeMessagePayloadData += payloadData
        }
        log.trace("ikeMessagePayloadData [${ikeMessagePayloadData.size}] " + ikeMessagePayloadData.toUByteArray().contentToString())
        return ikeMessagePayloadData
    }


    fun decode(nextPayload: UByte, rawData: ByteArray) {
        log.info("Decoding IKE payloads")

        var payloadType = nextPayload
        var data = rawData

        while (data.isNotEmpty()) {
            // bounds checking
            log.trace("rawData [${data.size}] = " + data.toUByteArray().contentToString())
            log.trace("DecodePayload(): Decode 1 payload")

            // Verifica se há bytes suficientes para decodificar o próximo payload
            if (data.size < 4) {
                throw Exception("DecodePayload(): No sufficient bytes to decode next payload")
            }

            val payloadLength = data.copyOfRange(2, 4).toShort().toInt()
            if (payloadLength < 4) {
                throw Exception("DecodePayload(): Illegal payload length $payloadLength < header length 4")
            }

            if (data.size < payloadLength) {
                throw Exception("DecodePayload(): The length of received message does not match the length specified in header")
            }

            val criticalBit = (data[1].toInt() and 0x80) ushr 7
            val payload: IKEPayload = when (payloadType) {
                IKEPayloadType.TypeSA.value -> SecurityAssociation()
                IKEPayloadType.TypeKE.value -> KeyExchange()
                IKEPayloadType.TypeIDi.value -> IdentificationInitiator()
                IKEPayloadType.TypeIDr.value -> IdentificationResponder()
                IKEPayloadType.TypeCERT.value -> Certificate()
                IKEPayloadType.TypeCERTreq.value -> CertificateRequest()
                IKEPayloadType.TypeAUTH.value-> Authentication()
                IKEPayloadType.TypeNiNr.value -> Nonce()
                IKEPayloadType.TypeN.value-> Notification()
                IKEPayloadType.TypeD.value -> Delete()
                IKEPayloadType.TypeV.value -> VendorID()
                IKEPayloadType.TypeTSi.value-> TrafficSelectorInitiator()
                IKEPayloadType.TypeTSr.value -> TrafficSelectorResponder()
                IKEPayloadType.TypeSK.value -> {
                    val encryptedPayload = Encrypted()
                    encryptedPayload.nextPayload = rawData[0].toUByte()
                    encryptedPayload
                }
                IKEPayloadType.TypeCP.value -> Configuration()
                IKEPayloadType.TypeEAP.value -> EAP()
                else -> {
                    if (criticalBit == 0) {
                        // Pula este payload
                        payloadType = data[0].toUByte()
                        data = data.drop(payloadLength).toByteArray()
                        continue
                    } else {
                        // Rejeita esta mensagem IKE
                        throw Exception("Unknown payload type: $nextPayload")
                    }
                }
            }

            payload.unmarshal(data.sliceArray(4 until payloadLength))
            add(payload)
            payloadType = data[0].toUByte()
            data = data.drop(payloadLength).toByteArray()
        }
    }

    fun reset() {
        clear()
    }

    fun buildNotification(protocolID: Byte, notifyMessageType: Int, spi: ByteArray?, notificationData: ByteArray?) {
        val notification = Notification()
        notification.protocolID = protocolID.toUByte()
        notification.notifyMessageType = notifyMessageType.toUShort()
        if (spi != null) {
            notification.spi += spi
        }
        if (notificationData != null) {
            notification.notificationData += notificationData
        }
        add(notification)
    }

    fun buildCertificate(certificateEncode: Byte, certificateData: ByteArray) {
        val certificate = Certificate()
        certificate.certificateEncoding = certificateEncode.toUByte()
        certificate.certificateData += certificateData
        add(certificate)
    }

    fun buildEncrypted(nextPayload: IKEPayloadType, encryptedData: ByteArray): Encrypted {
        val encrypted = Encrypted()
        encrypted.nextPayload = nextPayload.value
        encrypted.encryptedData += encryptedData
        add(encrypted)
        return encrypted
    }

    fun buildKeyExchange(diffiehellmanGroup: Short, keyExchangeData: ByteArray) {
        val keyExchange = KeyExchange()
        keyExchange.diffieHellmanGroup = diffiehellmanGroup.toUShort()
        keyExchange.keyExchangeData += keyExchangeData
        add(keyExchange)
    }

    fun buildIdentificationInitiator(idType: Byte, idData: ByteArray) {
        val identification = IdentificationInitiator()
        identification.idType = idType
        identification.idData += idData
        add(identification)
    }

    fun buildIdentificationResponder(idType: Byte, idData: ByteArray) {
        val identification = IdentificationResponder()
        identification.idType = idType
        identification.idData += idData
        add(identification)
    }

    fun buildAuthentication(authenticationMethod: Byte, authenticationData: ByteArray) {
        val authentication = Authentication()
        authentication.authenticationMethod = authenticationMethod.toUByte()
        authentication.authenticationData += authenticationData
        add(authentication)
    }

    fun buildConfiguration(configurationType: Byte): Configuration {
        val configuration = Configuration()
        configuration.configurationType = configurationType.toUByte()
        add(configuration)
        return configuration
    }

    fun buildNonce(nonceData: ByteArray) {
        val nonce = Nonce()
        nonce.nonceData += nonceData
        add(nonce)
    }

    fun buildTrafficSelectorInitiator(): TrafficSelectorInitiator {
        val trafficSelectorInitiator = TrafficSelectorInitiator()
        add(trafficSelectorInitiator)
        return trafficSelectorInitiator
    }

    fun buildTrafficSelectorResponder(): TrafficSelectorResponder {
        val trafficSelectorResponder = TrafficSelectorResponder()
        add(trafficSelectorResponder)
        return trafficSelectorResponder
    }

    fun buildSecurityAssociation(): SecurityAssociation {
        val securityAssociation = SecurityAssociation()
        add(securityAssociation)
        return securityAssociation
    }

    fun buildEAP(code: UByte, identifier: UByte): EAP {
        val eap = EAP()
        eap.code = code
        eap.identifier = identifier
        add(eap)
        return eap
    }

    fun buildEAPSuccess(identifier: UByte) {
        val eap = EAP()
        eap.code = EAPCode.EAPCodeSuccess.value
        eap.identifier = identifier
        add(eap)
    }

    fun buildEAPfailure(identifier: UByte) {
        val eap = EAP()
        eap.code = EAPCode.EAPCodeFailure.value
        eap.identifier = identifier
        add(eap)
    }

    fun buildEAP5GStart(identifier: UByte) {
        val eap = buildEAP(EAPCode.EAPCodeRequest.value, identifier)
        eap.eapTypeData.buildEAPExpanded(
            VendorID3GPP.toUInt(),
            VendorTypeEAP5G.toUInt(),
            byteArrayOf(EAP5GType.EAP5GType5GStart.value.toByte(), EAP5GSpareValue.toByte())
        )
    }

    fun buildEAP5GNAS(identifier: UByte, nasPDU: ByteArray) {
        if (nasPDU.isEmpty()) {
            log.error("BuildEAP5GNAS(): NASPDU is nil")
            return
        }
        val header = ByteArray(4)
        header[0] = EAP5GType.EAP5GType5GNAS.value.toByte()
        val lengthBytes = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(nasPDU.size.toShort()).array()
        header[2] = lengthBytes[0]
        header[3] = lengthBytes[1]
        val vendorData = header + nasPDU
        val eap = buildEAP(EAPCode.EAPCodeRequest.value, identifier)
        eap.eapTypeData.buildEAPExpanded(VendorID3GPP.toUInt(), VendorTypeEAP5G.toUInt(), vendorData)
    }

    fun buildNotify5gQosInfo(pduSessionID: UByte, qfiList: List<UByte>, isDefault: Boolean, isDSCPSpecified: Boolean, dscp: UByte) {
        val notifyData = mutableListOf<Byte>()
        notifyData.add(pduSessionID.toByte())
        notifyData.add(qfiList.size.toByte())
        notifyData.addAll(qfiList.map { it.toByte() })
        var defaultAndDifferentiatedServiceFlags: Byte = 0
        if (isDefault) {
            defaultAndDifferentiatedServiceFlags = (defaultAndDifferentiatedServiceFlags.toInt() or NotifyType5G_QOS_INFOBitDCSICheck.toInt()).toByte()
        }
        if (isDSCPSpecified) {
            defaultAndDifferentiatedServiceFlags = (defaultAndDifferentiatedServiceFlags.toInt() or NotifyType5G_QOS_INFOBitDSCPICheck.toInt()).toByte()
        }
        notifyData.add(defaultAndDifferentiatedServiceFlags)
        if (isDSCPSpecified) {
            notifyData.add(dscp.toByte())
        }
        notifyData[0] = notifyData.size.toByte()
        buildNotification(
            ProtocolType.TypeNone.value.toByte(),
            Vendor3GPPNotifyType5G_QOS_INFO.toInt(),
            null,
            notifyData.toByteArray()
        )
    }

    fun buildNotifyNasIP4Address(nasIPAddr: String) {
        if (nasIPAddr.isEmpty()) {
            return
        } else {
            val ipAddrByte = try {
                InetAddress.getByName(nasIPAddr).address
            } catch (e: UnknownHostException) {
                null
            }
            if (ipAddrByte != null) {
                buildNotification(
                    ProtocolType.TypeNone.value.toByte(),
                    Vendor3GPPNotifyTypeNAS_IP4_ADDRESS.toInt(),
                    null,
                    ipAddrByte
                )
            }
        }
    }

    fun buildNotifyUpIP4Address(upIPAddr: String) {
        if (upIPAddr.isEmpty()) {
            return
        } else {
            val ipAddrByte = try {
                InetAddress.getByName(upIPAddr).address
            } catch (e: UnknownHostException) {
                null
            }
            if (ipAddrByte != null) {
                buildNotification(
                    ProtocolType.TypeNone.value.toByte(),
                    Vendor3GPPNotifyTypeUP_IP4_ADDRESS.toInt(),
                    null,
                    ipAddrByte
                )
            }
        }
    }

    fun buildNotifyNasTcpPort(port: Short) {
        if (port == 0.toShort()) {
            return
        } else {
            val portData = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(port).array()
            buildNotification(
                ProtocolType.TypeNone.value.toByte(),
                Vendor3GPPNotifyTypeNAS_TCP_PORT.toInt(),
                null,
                portData
            )
        }
    }
}




interface IKEPayload {
    // Type specifies the IKE payload types
    fun type(): IKEPayloadType

    // Called by Encode() or Decode()
    fun marshal(): ByteArray
    fun unmarshal(rawData: ByteArray)
}


// Definition of Security Association
class SecurityAssociation : IKEPayload {
    var proposals: ProposalContainer = ProposalContainer()

    override fun type(): IKEPayloadType {
        return IKEPayloadType.TypeSA
    }

    override fun marshal(): ByteArray {
        log.info("[SecurityAssociation] marshal(): Start marshalling")

        var securityAssociationData = ByteArray(0)

        for ((proposalIndex, proposal) in this.proposals.withIndex()) {
            var proposalData = ByteArray(8)
            if (proposalIndex + 1 < this.proposals.size) {
                proposalData[0] = 2.toByte()
            } else {
                proposalData[0] = 0.toByte()
            }

            proposalData[4] = proposal.proposalNumber.toByte()
            proposalData[5] = proposal.protocolID.toByte()
            proposalData[6] = proposal.spi.size.toByte()

            if (proposal.spi.isNotEmpty()) {
                proposalData += proposal.spi
            }

            // Combine all transforms
            val transformList = mutableListOf<Transform>()
            transformList.addAll(proposal.encryptionAlgorithm.transforms)
            transformList.addAll(proposal.pseudorandomFunction.transforms)
            transformList.addAll(proposal.integrityAlgorithm.transforms)
            transformList.addAll(proposal.diffieHellmanGroup.transforms)
            transformList.addAll(proposal.extendedSequenceNumbers.transforms)

            if (transformList.isEmpty()) {
                throw Exception("One proposal has no any transform")
            }
            proposalData[7] = transformList.size.toByte()

            var proposalTransformData = ByteArray(0)
            for ((transformIndex, transform) in transformList.withIndex()) {
                var transformData = ByteArray(8)

                transformData[0] = if (transformIndex + 1 < transformList.size) 3 else 0
                transformData[4] = transform.transformType.toByte()
                ByteBuffer.wrap(transformData, 6, 2).order(ByteOrder.BIG_ENDIAN).putShort(transform.transformID.toShort()) // pos 6 e 7

                if (transform.attributePresent) {
                    var attributeData = ByteArray(4)
                    val attributeFormatAndType = ((transform.attributeFormat.toUInt() and 0x1u) shl 15) or transform.attributeType.toUInt()
                    ByteBuffer.wrap(attributeData, 0, 2).order(ByteOrder.BIG_ENDIAN).putShort(attributeFormatAndType.toShort())  // pos 0 e 1

                    if (transform.attributeFormat.toInt() == 0) {
                        // TLV
                        if (transform.variableLengthAttributeValue.isEmpty()) {
                            throw Exception("Attribute of one transform not specified")
                        }
                        ByteBuffer.wrap(attributeData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(transform.variableLengthAttributeValue.size.toShort())  // pos 2 e 3
                        attributeData += transform.variableLengthAttributeValue
                    } else {
                        // TV
                        ByteBuffer.wrap(attributeData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(transform.attributeValue.toShort())  // pos 2 e 3
                    }
                    log.trace("attributeData [${attributeData.size}] = ${attributeData.toUByteArray().contentToString()}")
                    transformData += attributeData
                }

                ByteBuffer.wrap(transformData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(transformData.size.toShort())  // pos 2 e 3

                log.trace("transformData [${transformData.size}] = ${transformData.toUByteArray().contentToString()}")
                proposalTransformData += transformData
            }

            log.trace("proposalTransformData [${proposalTransformData.size}] = ${proposalTransformData.toUByteArray().contentToString()}")
            log.trace("proposalData [${proposalData.size}] = ${proposalData.toUByteArray().contentToString()}")
            proposalData += proposalTransformData
            ByteBuffer.wrap(proposalData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(proposalData.size.toShort())  // pos 2 e 3

            securityAssociationData += proposalData
        }
        log.trace("securityAssociationData [${securityAssociationData.size}] = ${securityAssociationData.toUByteArray().contentToString()}")
        return securityAssociationData
    }


    override fun unmarshal(rawData: ByteArray) {
        log.info("[SecurityAssociation] unmarshal(): Start unmarshalling received bytes")
        log.trace("[SecurityAssociation] unmarshal(): Payload length ${rawData.size} bytes  ")

        var index = 0
        while (index < rawData.size) {
            log.trace("[SecurityAssociation] unmarshal(): Unmarshal 1 proposal")

            // bounds checking
            if (rawData.size - index < 8) {
                throw Exception("Proposal: No sufficient bytes to decode next proposal")
            }
            val proposalLength = ((rawData[index + 2].toInt() and 0xFF shl 8) or (rawData[index + 3].toInt() and 0xFF))
            if (proposalLength < 8) {
                throw Exception("Proposal: Illegal payload length $proposalLength < header length 8")
            }
            if (rawData.size - index < proposalLength) {
                throw Exception("Proposal: The length of received message not matches the length specified in header")
            }

            // Log whether this proposal is the last
            if (index == rawData.size-1) {
                log.trace("[SecurityAssociation] This proposal is the last")
            }
            // Log the number of transform in the proposal
            log.trace("[SecurityAssociation] This proposal contained %d transform  ${rawData[index + 7]} ")

            val proposal = Proposal()
            proposal.proposalNumber = rawData[index + 4].toUByte()
            proposal.protocolID = rawData[index + 5].toUByte()

            val spiSize = rawData[index + 6].toInt()
            if (spiSize > 0) {
                if (rawData.size - index < 8 + spiSize) {
                    throw Exception("Proposal: No sufficient bytes for unmarshalling SPI of proposal")
                }
                proposal.spi = rawData.copyOfRange(index + 8, index + 8 + spiSize)
            }

            var transformDataIndex = index + 8 + spiSize
            while (transformDataIndex < index + proposalLength) {
                if (rawData.size - transformDataIndex < 8) {
                    throw Exception("Transform: No sufficient bytes to decode next transform")
                }
                val transformLength = ((rawData[transformDataIndex + 2].toInt() and 0xFF shl 8) or (rawData[transformDataIndex + 3].toInt() and 0xFF))
                if (transformLength < 8) {
                    throw Exception("Transform: Illegal payload length $transformLength < header length 8")
                }
                if (rawData.size - transformDataIndex < transformLength) {
                    throw Exception("Transform: The length of received message not matches the length specified in header")
                }

                val transform = Transform()
                transform.transformType = rawData[transformDataIndex + 4].toUByte()
                transform.transformID = ((rawData[transformDataIndex + 6].toInt() shl 8) or rawData[transformDataIndex + 7].toInt()).toUShort()

                if (transformLength > 8) {
                    transform.attributePresent = true
                    transform.attributeFormat = ((rawData[transformDataIndex + 8].toInt() and 0x80) shr 7).toUByte()
                    transform.attributeType = ((rawData[transformDataIndex + 8].toInt() shl 8) or rawData[transformDataIndex + 9].toInt() and 0x7fff).toUShort()

                    if (transform.attributeFormat.toInt() == 0) {
                        val attributeLength = ((rawData[transformDataIndex + 10].toInt() shl 8) or rawData[transformDataIndex + 11].toInt())
                        if (12 + attributeLength != transformLength) {
                            throw Exception("Illegal attribute length $attributeLength not satisfies the transform length $transformLength")
                        }
                        transform.variableLengthAttributeValue = rawData.copyOfRange(transformDataIndex + 12, transformDataIndex + 12 + attributeLength)
                    } else {
                        transform.attributeValue = ((rawData[transformDataIndex + 10].toInt() shl 8) or rawData[transformDataIndex + 11].toInt()).toUShort()
                    }
                }

                when (transform.transformType) {
                    PayloadType.TypeEncryptionAlgorithm.value.toUByte() -> proposal.encryptionAlgorithm.transforms.add(transform)
                    PayloadType.TypePseudorandomFunction.value.toUByte() -> proposal.pseudorandomFunction.transforms.add(transform)
                    PayloadType.TypeIntegrityAlgorithm.value.toUByte() -> proposal.integrityAlgorithm.transforms.add(transform)
                    PayloadType.TypeDiffieHellmanGroup.value.toUByte() -> proposal.diffieHellmanGroup.transforms.add(transform)
                    PayloadType.TypeExtendedSequenceNumbers.value.toUByte() -> proposal.extendedSequenceNumbers.transforms.add(transform)
                }

                transformDataIndex += transformLength
            }

            proposals.add(proposal)
            index += proposalLength
        }
    }
}



class IKEMessage {
    var initiatorSPI: ULong = 0u
    var responderSPI: ULong = 0u
    var version: UByte = 0u
    var exchangeType: UByte = 0u
    var flags: UByte = 0u
    var messageID: UInt = 0u
    var payloads: IKEPayloadContainer = IKEPayloadContainer()

    fun buildIKEHeader(
        initiatorSPI: ULong,
        responsorSPI: ULong,
        exchangeType: UByte,
        flags: UByte,
        messageID: UInt
    ) {
        this.initiatorSPI = initiatorSPI
        this.responderSPI = responsorSPI
        this.version = 0x20u
        this.exchangeType = exchangeType
        this.flags = flags
        this.messageID = messageID
    }

    fun encode(): ByteArray {
        log.info("Encoding IKE message")

        var ikeMessageData = ByteArray(28)

        ByteBuffer.wrap(ikeMessageData, 0, 8).order(ByteOrder.BIG_ENDIAN).putLong(initiatorSPI.toLong())  // pos 0 a 7
        ByteBuffer.wrap(ikeMessageData, 8, 8).order(ByteOrder.BIG_ENDIAN).putLong(responderSPI.toLong())  // pos 8 a 15
        ikeMessageData[17] = version.toByte()
        ikeMessageData[18] = exchangeType.toByte()
        ikeMessageData[19] = flags.toByte()
        ByteBuffer.wrap(ikeMessageData, 20, 4).order(ByteOrder.BIG_ENDIAN).putInt(messageID.toInt())  // pos 20 a 23

        if (payloads.isNotEmpty()) {
            ikeMessageData[16] = payloads[0].type().value.toByte()
        } else {
            ikeMessageData[16] = IKEPayloadType.NoNext.value.toByte()
        }

        val ikeMessagePayloadData = payloads.encode()
        ikeMessageData += ikeMessagePayloadData

        ByteBuffer.wrap(ikeMessageData, 24, 4).order(ByteOrder.BIG_ENDIAN).putInt(ikeMessageData.size)  // pos 24 a 27
        return ikeMessageData
    }

    fun decode(rawData: ByteArray) {
        // IKE message packet format this implementation referenced is
        // defined in RFC 7296, Section 3.1
        log.info("Decoding IKE message")
        log.trace("Received IKE message: [${(rawData.size)}] ${rawData.toUByteArray().contentToString()}")

        // bounds checking
        if (rawData.size < 28) {
            throw Exception("Decode(): Received broken IKE header")
        }

        val ikeMessageLength = ByteBuffer.wrap(rawData, 24, 4).order(ByteOrder.BIG_ENDIAN).int
        if (ikeMessageLength < 28) {
            throw Exception("Decode(): Illegal IKE message length $ikeMessageLength < header length 20")
        }

        // len() return int, which is 64 bit on 64-bit host and 32 bit
        // on 32-bit host, so this implementation may potentially cause
        // problem on 32-bit machine
        if (rawData.size != ikeMessageLength) {
            throw Exception("Decode(): The length of received message not matches the length specified in header")
        }

        val nextPayload = rawData[16]
        initiatorSPI = ByteBuffer.wrap(rawData, 0, 8).order(ByteOrder.BIG_ENDIAN).long.toULong()
        responderSPI = ByteBuffer.wrap(rawData, 8, 8).order(ByteOrder.BIG_ENDIAN).long.toULong()
        version = rawData[17].toUByte()
        exchangeType = rawData[18].toUByte()
        flags = rawData[19].toUByte()
        messageID = ByteBuffer.wrap(rawData, 20, 4).order(ByteOrder.BIG_ENDIAN).int.toUInt()

        payloads.decode(nextPayload.toUByte(), rawData.copyOfRange(28, rawData.size))
    }
}



// Definition of Key Exchange
class KeyExchange: IKEPayload {
    var diffieHellmanGroup: UShort = 0u
    var keyExchangeData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(KeyExchange::class.java)
    }
    override fun type(): IKEPayloadType = IKEPayloadType.TypeKE

    override fun marshal(): ByteArray {
        log.info("[KeyExchange] marshal(): Start marshalling")
        var keyExchangeDataByteArray = ByteArray(4)
        ByteBuffer.wrap(keyExchangeDataByteArray, 0, 2).order(ByteOrder.BIG_ENDIAN).putShort(diffieHellmanGroup.toShort())  // pos 0 e 1
        keyExchangeDataByteArray += keyExchangeData
        return keyExchangeDataByteArray
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[KeyExchange] unmarshal(): Start unmarshalling received bytes")
        log.trace("[KeyExchange] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[KeyExchange] unmarshal(): Unmarshal 1 key exchange data")

            if (rawData.size <= 4) {
                throw Exception("KeyExchange: No sufficient bytes to decode next key exchange data")
            }
            diffieHellmanGroup = ByteBuffer.wrap(rawData, 0, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
            keyExchangeData = rawData.copyOfRange(4, rawData.size)
        }
    }
}



// Definition of Certificate
class Certificate: IKEPayload {
    var certificateEncoding: UByte = 0u
    var certificateData: ByteArray = byteArrayOf()

    companion object {
        val log: Logger = LoggerFactory.getLogger(Certificate::class.java)
    }

    override fun type(): IKEPayloadType = IKEPayloadType.TypeCERT

    override fun marshal(): ByteArray {
        log.info("[Certificate] marshal(): Start marshalling")
        val certificateData = ByteArray(1)
        certificateData[0] = certificateEncoding.toByte()
        return certificateData + this.certificateData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Certificate] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Certificate] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[Certificate] unmarshal(): Unmarshal 1 certificate")

            if (rawData.size <= 1) {
                throw Exception("Certificate: No sufficient bytes to decode next certificate")
            }
            certificateEncoding = rawData[0].toUByte()
            certificateData += rawData.copyOfRange(1, rawData.size)
        }
    }
}



// Definition of Certificate Request
class CertificateRequest: IKEPayload {
    var certificateEncoding: UByte = 0u
    var certificationAuthority: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(CertificateRequest::class.java)
    }

    override fun type(): IKEPayloadType = IKEPayloadType.TypeCERTreq

    override fun marshal(): ByteArray {
        log.info("[CertificateRequest] marshal(): Start marshalling")
        val certificateRequestData = ByteArray(1)
        certificateRequestData[0] = certificateEncoding.toByte()
        return certificateRequestData + this.certificationAuthority
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[CertificateRequest] unmarshal(): Start unmarshalling received bytes")
        log.trace("[CertificateRequest] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[CertificateRequest] unmarshal(): Unmarshal 1 certificate request")

            if (rawData.size <= 1) {
                throw Exception("CertificateRequest: No sufficient bytes to decode next certificate request")
            }
            certificateEncoding = rawData[0].toUByte()
            certificationAuthority += rawData.copyOfRange(1, rawData.size)
        }
    }
}



// Definition of Authentication
class Authentication: IKEPayload {
    var authenticationMethod: UByte = 0u
    var authenticationData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(Authentication::class.java)
    }

    override fun type(): IKEPayloadType = IKEPayloadType.TypeAUTH

    override fun marshal(): ByteArray {
        log.info("[Authentication] marshal(): Start marshalling")
        val authenticationData = ByteArray(4)
        authenticationData[0] = this.authenticationMethod.toByte()
        return authenticationData + this.authenticationData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Authentication] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Authentication] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[Authentication] unmarshal(): Unmarshal 1 authentication")

            if (rawData.size <= 4) {
                throw Exception("Authentication: No sufficient bytes to decode next authentication")
            }
            authenticationMethod = rawData[0].toUByte()
            authenticationData += rawData.copyOfRange(4, rawData.size)
        }
    }
}



// Definition of Notification
class Notification : IKEPayload {
    var protocolID: UByte = 0u
    var notifyMessageType: UShort = 0u
    var spi: ByteArray = ByteArray(0)
    var notificationData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(Notification::class.java)
    }

    override fun type(): IKEPayloadType {
        return IKEPayloadType.TypeN
    }

    override fun marshal(): ByteArray {
        log.info("[Notification] marshal(): Start marshalling")
        var notificationData = ByteArray(4)
        notificationData[0] = protocolID.toByte()
        notificationData[1] = spi.size.toByte()
        ByteBuffer.wrap(notificationData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(notifyMessageType.toShort())  // pos 2 e 3

        notificationData += spi
        notificationData += this.notificationData
        return notificationData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Notification] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Notification] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[Notification] unmarshal(): Unmarshal 1 notification")

            if (rawData.size < 4) {
                throw Exception("Notification: No sufficient bytes to decode next notification")
            }
            val spiSize = rawData[1].toInt()
            if (rawData.size < 4 + spiSize) {
                throw Exception("Notification: No sufficient bytes to get SPI according to the length specified in header")
            }
            protocolID = rawData[0].toUByte()
            notifyMessageType = ByteBuffer.wrap(rawData, 2, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
            spi = rawData.copyOfRange(4, 4 + spiSize)
            notificationData = rawData.copyOfRange(4 + spiSize, rawData.size)
        }
    }
}



// Definition of Nonce
class Nonce : IKEPayload {
    var nonceData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(Nonce::class.java)
    }

    override fun type(): IKEPayloadType {
        return IKEPayloadType.TypeNiNr
    }

    override fun marshal(): ByteArray {
        log.info("[Nonce] marshal(): Start marshalling")
        return nonceData.copyOf()
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Nonce] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Nonce] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[Nonce] unmarshal(): Unmarshal 1 nonce")
            nonceData += rawData
        }
    }
}



// Definition of Vendor ID
class VendorID : IKEPayload {
    var vendorIDData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(VendorID::class.java)
    }

    override fun type(): IKEPayloadType {
        return IKEPayloadType.TypeV
    }

    override fun marshal(): ByteArray {
        log.info("[VendorID] marshal(): Start marshalling")
        return vendorIDData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[VendorID] unmarshal(): Start unmarshalling received bytes")
        log.trace("[VendorID] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[VendorID] unmarshal(): Unmarshal 1 vendor ID")
            vendorIDData += rawData
        }
    }
}



// Definition of Identification - Initiator
class IdentificationInitiator: IKEPayload {
    var idType: Byte = 0
    var idData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(IdentificationInitiator::class.java)
    }
    override fun type(): IKEPayloadType = IKEPayloadType.TypeIDi

    override fun marshal(): ByteArray {
        log.info("[Identification] marshal(): Start marshalling")
        var identificationData = ByteArray(4)
        identificationData[0] = idType
        identificationData += idData
        log.trace("identificationData [${identificationData.size}] " + identificationData.toUByteArray().contentToString())
        return identificationData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Identification] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Identification] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[Identification] unmarshal(): Unmarshal 1 identification")

            if (rawData.size <= 4) {
                throw Exception("Identification: No sufficient bytes to decode next identification")
            }
            idType = rawData[0]
            idData = rawData.copyOfRange(4, rawData.size)
        }
    }
}



// Definition of Identification - Responder
class IdentificationResponder: IKEPayload {
    var idType: Byte = 0
    var idData: ByteArray = ByteArray(0)

    override fun type(): IKEPayloadType = IKEPayloadType.TypeIDr

    override fun marshal(): ByteArray {
        log.info("[Identification] marshal(): Start marshalling")
        val identificationData = ByteArray(4)
        identificationData[0] = idType
        return identificationData + idData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Identification] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Identification] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[Identification] unmarshal(): Unmarshal 1 identification")

            if (rawData.size <= 4) {
                throw Exception("Identification: No sufficient bytes to decode next identification")
            }
            idType = rawData[0]
            idData = rawData.copyOfRange(4, rawData.size)
        }
    }
}



// Definition of Delete
class Delete : IKEPayload {
    var protocolID: UByte = 0u
    var spiSize: UByte = 0u
    var numberOfSPI: UShort = 0u
    var spis: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(Delete::class.java)
    }

    override fun type(): IKEPayloadType {
        return IKEPayloadType.TypeD
    }

    override fun marshal(): ByteArray {
        log.info("[Delete] marshal(): Start marshalling")
        if (spis.size != (spiSize.toInt() * numberOfSPI.toInt())) {
            throw Exception("Total bytes of all SPIs not correct")
        }
        var deleteData = ByteArray(4)
        deleteData[0] = protocolID.toByte()
        deleteData[1] = spiSize.toByte()
        ByteBuffer.wrap(deleteData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(numberOfSPI.toShort())  // pos 2 e 3

        deleteData += spis
        return deleteData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Delete] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Delete] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[Delete] unmarshal(): Unmarshal 1 delete")

            if (rawData.size <= 4) {
                throw Exception("Delete: No sufficient bytes to decode next delete")
            }
            val buffer = ByteBuffer.wrap(rawData)
            buffer.order(ByteOrder.BIG_ENDIAN)
            val spiSize = buffer.get().toUByte()
            val numberOfSPI = buffer.short.toUShort()
            if (rawData.size < (4 + (spiSize.toInt() * numberOfSPI.toInt()))) {
                throw Exception("Delete: No Sufficient bytes to get SPIs according to the length specified in header")
            }
            protocolID = buffer.get().toUByte()
            this.spiSize = spiSize
            this.numberOfSPI = numberOfSPI
            spis = rawData.copyOfRange(4, rawData.size)
        }
    }
}



// Definition of Encrypted Payload
class Encrypted: IKEPayload {
    var nextPayload: UByte = 0u
    var encryptedData: ByteArray = byteArrayOf()

    companion object {
        val log: Logger = LoggerFactory.getLogger(Delete::class.java)
    }

    override fun type() = IKEPayloadType.TypeSK

    override fun marshal(): ByteArray {
        log.info("[Encrypted] marshal(): Start marshalling")
        if (encryptedData.isEmpty()) {
            log.warn("[Encrypted] The encrypted data is empty")
        }
        return encryptedData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Encrypted] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Encrypted] unmarshal(): Payload length ${rawData.size} bytes")
        encryptedData += rawData
    }
}



class IndividualConfigurationAttribute(
    var type: UShort,
    var value: ByteArray
)


class ConfigurationAttributeContainer {
    var attributes: MutableList<IndividualConfigurationAttribute> = mutableListOf()

    fun buildConfigurationAttribute(attributeType: UShort, attributeValue: ByteArray) {
        val configurationAttribute = IndividualConfigurationAttribute(attributeType, attributeValue)
        this.attributes.add(configurationAttribute)
    }

    fun reset() {
        this.attributes.clear()
    }
}



// Definition of Configuration
class Configuration: IKEPayload {
    var configurationType: UByte = 0u
    var configurationAttribute = ConfigurationAttributeContainer()

    companion object {
        val log: Logger = LoggerFactory.getLogger(Configuration::class.java)
    }

    override fun type() = IKEPayloadType.TypeCP

    override fun marshal(): ByteArray {
        log.info("[Configuration] marshal(): Start marshalling")
        var configurationData = ByteArray(4)
        configurationData[0] = configurationType.toByte()

        for (attribute in configurationAttribute.attributes) {
            var attributeData = ByteArray(4)
            ByteBuffer.wrap(attributeData, 0, 2).order(ByteOrder.BIG_ENDIAN).putShort((attribute.type.toInt() and 0x7fff).toShort())  // pos 0 e 1
            ByteBuffer.wrap(attributeData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(attribute.value.size.toShort())  // pos 2 e 3
            attributeData += attribute.value

            configurationData += attributeData
        }
        return configurationData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[Configuration] unmarshal(): Start unmarshalling received bytes")
        log.trace("[Configuration] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[Configuration] unmarshal(): Unmarshal 1 configuration")
            if (rawData.size <= 4) {
                throw Exception("Configuration: No sufficient bytes to decode next configuration")
            }
            configurationType = rawData[0].toUByte()
            var configurationAttributeData = rawData.sliceArray(4 until rawData.size)
            while (configurationAttributeData.isNotEmpty()) {
                log.trace("[Configuration] unmarshal(): Unmarshal 1 configuration attribute")
                if (configurationAttributeData.size < 4) {
                    throw Exception("ConfigurationAttribute: No sufficient bytes to decode next configuration attribute")
                }
                val length = ByteBuffer.wrap(configurationAttributeData.sliceArray(2..3)).order(ByteOrder.BIG_ENDIAN).short.toInt()
                if (configurationAttributeData.size < 4 + length) {
                    throw Exception("ConfigurationAttribute: TLV attribute length error")
                }
                val individualConfigurationAttribute = IndividualConfigurationAttribute(
                    type = ByteBuffer.wrap(configurationAttributeData.sliceArray(0..1)).order(ByteOrder.BIG_ENDIAN).short.toUShort(),
                    value = configurationAttributeData.sliceArray(4 until 4 + length)
                )
                configurationAttributeData = configurationAttributeData.sliceArray(4 + length until configurationAttributeData.size)
                configurationAttribute.attributes.add(individualConfigurationAttribute)
            }
        }
    }
}



// Definition of IKE EAP
class EAP: IKEPayload {
    var code: UByte = 0u
    var identifier: UByte = 0u
    var eapTypeData = EAPTypeDataContainer()

    companion object {
        val log: Logger = LoggerFactory.getLogger(EAP::class.java)
    }

    override fun type(): IKEPayloadType {
        return IKEPayloadType.TypeEAP
    }

    override fun marshal(): ByteArray {
        log.info("[EAP] marshal(): Start marshalling")

        var eapData = ByteArray(4)
        eapData[0] = code.toByte()
        eapData[1] = identifier.toByte()

        if (eapTypeData.isNotEmpty()) {
            eapData += eapTypeData[0].marshal()
        }
        ByteBuffer.wrap(eapData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(eapData.size.toShort())  // pos 2 e 3

        return eapData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[EAP] unmarshal(): Start unmarshalling received bytes")
        log.trace("[EAP] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            log.trace("[EAP] unmarshal(): Unmarshal 1 EAP")
            if (rawData.size < 4) {
                throw Exception("EAP: No sufficient bytes to decode next EAP payload")
            }

            val eapPayloadLength = ByteBuffer.wrap(rawData, 2, 2).short.toInt()
            if (eapPayloadLength < 4) {
                throw Exception("EAP: Payload length specified in the header is too small for EAP")
            }
            if (rawData.size != eapPayloadLength) {
                throw Exception("EAP: Received payload length not matches the length specified in header")
            }

            code = rawData[0].toUByte()
            identifier = rawData[1].toUByte()

            // EAP Success or Failed
            if (eapPayloadLength == 4) {
                return
            }

            val rawDataUByteArray  = rawData.toUByteArray()
            val eapType = rawDataUByteArray[4].toUInt()
            val eapTypeDataInstance: EAPTypeFormat = when (eapType) {
                EAPType.EAPTypeIdentity.value.toUInt() -> EAPIdentity()
                EAPType.EAPTypeNotification.value.toUInt() -> EAPNotification()
                EAPType.EAPTypeNak.value.toUInt() -> EAPNak()
                EAPType.EAPTypeExpanded.value.toUInt() -> EAPExpanded()
                else -> throw Exception("EAP: Not supported EAP type")
            }

            eapTypeDataInstance.unmarshal(rawData.copyOfRange(4, rawData.size))
            eapTypeData.add(eapTypeDataInstance)
        }
    }
}



class EAPTypeDataContainer: ArrayList<EAPTypeFormat>() {
    fun reset() {
        clear()
    }

    fun buildEAPExpanded(vendorID: UInt, vendorType: UInt, vendorData: ByteArray) {
        val eapExpanded = EAPExpanded()
        eapExpanded.vendorID = vendorID
        eapExpanded.vendorType = vendorType
        eapExpanded.vendorData = vendorData
        this.add(eapExpanded)
    }
}


interface EAPTypeFormat {
    fun type(): EAPType
    fun marshal(): ByteArray
    fun unmarshal(rawData: ByteArray)
}



// Definition of EAP Identity
class EAPIdentity : EAPTypeFormat {
    var identityData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(EAPIdentity::class.java)
    }

    override fun type(): EAPType {
        return EAPType.EAPTypeIdentity
    }

    override fun marshal(): ByteArray {
        log.info("[EAP][Identity] marshal(): Start marshalling")
        if (identityData.isEmpty()) {
            throw Exception("EAPIdentity: EAP identity is empty")
        }
        var eapIdentityData = byteArrayOf(EAPType.EAPTypeIdentity.value.toByte())
        eapIdentityData += identityData
        return eapIdentityData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[EAP][Identity] unmarshal(): Start unmarshalling received bytes")
        log.trace("[EAP][Identity] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.size > 1) {
            identityData += rawData.sliceArray(1 until rawData.size)
        }
    }
}



// Definition of EAP Notification
class EAPNotification: EAPTypeFormat {
    var notificationData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(EAPNotification::class.java)
    }

    override fun type(): EAPType {
        return EAPType.EAPTypeNotification
    }

    override fun marshal(): ByteArray {
        log.info("[EAP][Notification] marshal(): Start marshalling")
        if (notificationData.isEmpty()) {
            throw Exception("EAPNotification: EAP notification is empty")
        }

        var eapNotificationData = byteArrayOf(EAPType.EAPTypeNotification.value.toByte())
        eapNotificationData += notificationData
        return eapNotificationData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[EAP][Notification] unmarshal(): Start unmarshalling received bytes")
        log.trace("[EAP][Notification] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.size > 1) {
            notificationData += rawData.sliceArray(1 until rawData.size)
        }
    }
}



// Definition of EAP Nak
class EAPNak: EAPTypeFormat {
    var nakData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(EAPNak::class.java)
    }

    override fun type(): EAPType {
        return EAPType.EAPTypeNak
    }

    override fun marshal(): ByteArray {
        log.info("[EAP][Nak] marshal(): Start marshalling")
        if (nakData.isEmpty()) {
            throw Exception(null, Error("EAPNak: EAP nak is empty"))
        }
        var eapNakData = byteArrayOf(EAPType.EAPTypeNak.value.toByte())
        eapNakData += nakData
        return eapNakData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[EAP][Nak] unmarshal(): Start unmarshalling received bytes")
        log.trace("[EAP][Nak] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.size > 1) {
            nakData += rawData.sliceArray(1 until rawData.size)
        }
    }
}



// Definition of EAP expanded
class EAPExpanded: EAPTypeFormat {
    var vendorID: UInt = 0u
    var vendorType: UInt = 0u
    var vendorData: ByteArray = ByteArray(0)

    companion object {
        val log: Logger = LoggerFactory.getLogger(EAPExpanded::class.java)
    }

    override fun type(): EAPType {
        return EAPType.EAPTypeExpanded
    }

    override fun marshal(): ByteArray {
        log.info("[EAP][Expanded] marshal(): Start marshalling")
        val eapExpandedData = ByteArray(8)

        val vendorIDMasked = vendorID and 0x00FFFFFFu
        val typeAndVendorID = (EAPType.EAPTypeExpanded.value.toInt() shl 24) or vendorIDMasked.toInt()

        ByteBuffer.wrap(eapExpandedData, 0, 4).order(ByteOrder.BIG_ENDIAN).putInt(typeAndVendorID)  // pos 0 a 3
        ByteBuffer.wrap(eapExpandedData, 4, 4).order(ByteOrder.BIG_ENDIAN).putInt(vendorType.toInt())  // pos 4 a 7

        if (vendorData.isEmpty()) {
            log.warn("[EAP][Expanded] marshal(): EAP vendor data field is empty")
            return eapExpandedData
        }
        return eapExpandedData + vendorData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[EAP][Expanded] unmarshal(): Start unmarshalling received bytes")
        log.trace("[EAP][Expanded] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            if (rawData.size < 8) {
                throw Exception("EAPExpanded: No sufficient bytes to decode the EAP expanded type")
            }
            val typeAndVendorID = ByteBuffer.wrap(rawData, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt().toUInt()  // pos 0 a 4
            vendorID = typeAndVendorID and 0x00FFFFFFu
            vendorType = ByteBuffer.wrap(rawData, 4, 4).order(ByteOrder.BIG_ENDIAN).getInt().toUInt()  // pos 4 a 8
            if (rawData.size > 8) {
                vendorData += rawData.sliceArray(8 until rawData.size)
            }
        }
    }
}



// Definition of Traffic Selector - Initiator
class TrafficSelectorInitiator : IKEPayload {
    companion object {
        val log: Logger = LoggerFactory.getLogger(TrafficSelectorInitiator::class.java)
    }

    var trafficSelectors: IndividualTrafficSelectorContainer = IndividualTrafficSelectorContainer()


    override fun type(): IKEPayloadType {
        return IKEPayloadType.TypeTSi
    }

    override fun marshal(): ByteArray {
        log.info("[TrafficSelectorInitiator] marshal(): Start marshalling")

        if (trafficSelectors.isEmpty()) {
            throw Exception("TrafficSelector: Contains no traffic selector for marshalling message")
        }

        var trafficSelectorData = ByteArray(4)
        trafficSelectorData[0] = trafficSelectors.size.toByte()

        log.trace("trafficSelectorData [${trafficSelectorData.size}] = ${trafficSelectorData.toUByteArray().contentToString()}")

        for (selector in trafficSelectors) {
            if (selector.tsType == TS_IPV4_ADDR_RANGE) {
                if (selector.startAddress.size != 4 || selector.endAddress.size != 4) {
                    throw Exception("TrafficSelector: IPv4 address length is not correct")
                }
            } else if (selector.tsType == TS_IPV6_ADDR_RANGE) {
                if (selector.startAddress.size != 16 || selector.endAddress.size != 16) {
                    throw Exception("TrafficSelector: IPv6 address length is not correct")
                }
            } else {
                throw Exception("TrafficSelector: Unsupported traffic selector type")
            }

            var individualTrafficSelectorData = ByteArray(8)
            individualTrafficSelectorData[0] = selector.tsType.toByte()
            individualTrafficSelectorData[1] = selector.ipProtocolID.toByte()
            ByteBuffer.wrap(individualTrafficSelectorData, 4, 2).order(ByteOrder.BIG_ENDIAN).putShort(selector.startPort.toShort())  // pos 4 e 5
            ByteBuffer.wrap(individualTrafficSelectorData, 6, 2).order(ByteOrder.BIG_ENDIAN).putShort(selector.endPort.toShort())  // pos 6 e 7
            individualTrafficSelectorData += selector.startAddress
            individualTrafficSelectorData += selector.endAddress
            ByteBuffer.wrap(individualTrafficSelectorData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(individualTrafficSelectorData.size.toShort())  // pos 2 e 3
            log.trace("individualTrafficSelectorData [${individualTrafficSelectorData.size}] = ${individualTrafficSelectorData.toUByteArray().contentToString()}")

            trafficSelectorData += individualTrafficSelectorData
        }
        log.trace("trafficSelectorData [${trafficSelectorData.size}] = ${trafficSelectorData.toUByteArray().contentToString()}")
        return trafficSelectorData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[TrafficSelectorInitiator] unmarshal(): Start unmarshalling received bytes")
        log.trace("[TrafficSelectorInitiator] unmarshal(): Payload length ${rawData.size} bytes")
        if (rawData.isNotEmpty()) {
            var data = rawData.copyOf()
            if (data.size < 4) {
                throw IllegalArgumentException("TrafficSelector: No sufficient bytes to get number of traffic selector in header")
            }
            val numberOfSPI = data[0]
            data = data.copyOfRange(4, data.size)
            for (i in 0 until numberOfSPI) {
                if (data.size < 4) {
                    throw IllegalArgumentException("TrafficSelector: No sufficient bytes to decode next individual traffic selector length in header")
                }
                val trafficSelectorType = data[0]
                if (trafficSelectorType == TS_IPV4_ADDR_RANGE.toByte()) {
                    val selectorLength = ByteBuffer.wrap(data, 2, 2).order(ByteOrder.BIG_ENDIAN).short
                    if (selectorLength != 16.toShort()) {
                        throw IllegalArgumentException("TrafficSelector: A TS_IPV4_ADDR_RANGE type traffic selector should have length 16 bytes")
                    }
                    if (data.size < selectorLength) {
                        throw IllegalArgumentException("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
                    }
                    val individualTrafficSelector = IndividualTrafficSelector()
                    individualTrafficSelector.tsType = data[0].toUByte()
                    individualTrafficSelector.ipProtocolID = data[1].toUByte()
                    individualTrafficSelector.startPort = ByteBuffer.wrap(data, 4, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
                    individualTrafficSelector.endPort = ByteBuffer.wrap(data, 6, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
                    individualTrafficSelector.startAddress = data.copyOfRange(8, 12)
                    individualTrafficSelector.endAddress = data.copyOfRange(12, 16)
                    trafficSelectors.add(individualTrafficSelector)
                    data = data.copyOfRange(16, data.size)
                } else if (trafficSelectorType == TS_IPV6_ADDR_RANGE.toByte()) {
                    val selectorLength = ByteBuffer.wrap(data, 2, 2).order(ByteOrder.BIG_ENDIAN).short
                    if (selectorLength != 40.toShort()) {
                        throw IllegalArgumentException("TrafficSelector: A TS_IPV6_ADDR_RANGE type traffic selector should have length 40 bytes")
                    }
                    if (data.size < selectorLength) {
                        throw IllegalArgumentException("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
                    }
                    val individualTrafficSelector = IndividualTrafficSelector()
                    individualTrafficSelector.tsType = data[0].toUByte()
                    individualTrafficSelector.ipProtocolID = data[1].toUByte()
                    individualTrafficSelector.startPort = ByteBuffer.wrap(data, 4, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
                    individualTrafficSelector.endPort = ByteBuffer.wrap(data, 6, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
                    individualTrafficSelector.startAddress = data.copyOfRange(8, 24)
                    individualTrafficSelector.endAddress = data.copyOfRange(24, 40)
                    trafficSelectors.add(individualTrafficSelector)
                    data = data.copyOfRange(40, data.size)
                } else {
                    throw IllegalArgumentException("TrafficSelector: Unsupported traffic selector type")
                }
            }
        }
    }
}



class IndividualTrafficSelector {
    var tsType: UByte = 0u
    var ipProtocolID: UByte = 0u
    var startPort: UShort = 0u
    var endPort: UShort = 0u
    var startAddress: ByteArray = byteArrayOf()
    var endAddress: ByteArray = byteArrayOf()
}



class IndividualTrafficSelectorContainer : ArrayList<IndividualTrafficSelector>() {
    fun reset() {
        clear()
    }

    fun buildIndividualTrafficSelector(
        tsType: UByte,
        ipProtocolID: UByte,
        startPort: UShort,
        endPort: UShort,
        startAddr: ByteArray,
        endAddr: ByteArray
    ) {
        val trafficSelector = IndividualTrafficSelector()
        trafficSelector.tsType = tsType
        trafficSelector.ipProtocolID = ipProtocolID
        trafficSelector.startPort = startPort
        trafficSelector.endPort = endPort
        trafficSelector.startAddress = startAddr
        trafficSelector.endAddress = endAddr
        add(trafficSelector)
    }
}



val TS_IPV4_ADDR_RANGE: UByte = 7u
val TS_IPV6_ADDR_RANGE: UByte = 8u



// Definition of Traffic Selector - Responder
class TrafficSelectorResponder : IKEPayload {
    var trafficSelectors: IndividualTrafficSelectorContainer = IndividualTrafficSelectorContainer()

    companion object {
        val log: Logger = LoggerFactory.getLogger(TrafficSelectorResponder::class.java)
    }

    override fun type(): IKEPayloadType {
        return IKEPayloadType.TypeTSr
    }

    override fun marshal(): ByteArray {
        log.info("[TrafficSelectorResponder] marshal(): Start marshalling")

        if (trafficSelectors.isEmpty()) {
            throw Exception("TrafficSelector: Contains no traffic selector for marshalling message")
        }

        var trafficSelectorData = ByteArray(4)
        trafficSelectorData[0] = trafficSelectors.size.toByte()

        log.trace("trafficSelectorData [${trafficSelectorData.size}] = ${trafficSelectorData.toUByteArray().contentToString()}")

        for (individualTrafficSelector in trafficSelectors) {
            if (individualTrafficSelector.tsType == TS_IPV4_ADDR_RANGE) {
                if (individualTrafficSelector.startAddress.size != 4) {
                    throw Exception("TrafficSelector: Start IPv4 address length is not correct")
                }
                if (individualTrafficSelector.endAddress.size != 4) {
                    throw Exception("TrafficSelector: End IPv4 address length is not correct")
                }
            } else if (individualTrafficSelector.tsType == TS_IPV6_ADDR_RANGE) {
                if (individualTrafficSelector.startAddress.size != 16) {
                    throw Exception("TrafficSelector: Start IPv6 address length is not correct")
                }
                if (individualTrafficSelector.endAddress.size != 16) {
                    throw Exception("TrafficSelector: End IPv6 address length is not correct")
                }
            } else {
                throw Exception("TrafficSelector: Unsupported traffic selector type")
            }

            var individualTrafficSelectorData = ByteArray(8)
            individualTrafficSelectorData[0] = individualTrafficSelector.tsType.toByte()
            individualTrafficSelectorData[1] = individualTrafficSelector.ipProtocolID.toByte()
            ByteBuffer.wrap(individualTrafficSelectorData, 4, 2).order(ByteOrder.BIG_ENDIAN).putShort(individualTrafficSelector.startPort.toShort())
            ByteBuffer.wrap(individualTrafficSelectorData, 6, 2).order(ByteOrder.BIG_ENDIAN).putShort(individualTrafficSelector.endPort.toShort())
            individualTrafficSelectorData += individualTrafficSelector.startAddress
            individualTrafficSelectorData += individualTrafficSelector.endAddress
            ByteBuffer.wrap(individualTrafficSelectorData, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(individualTrafficSelectorData.size.toShort())

            log.trace("individualTrafficSelectorData [${individualTrafficSelectorData.size}] = ${individualTrafficSelectorData.toUByteArray().contentToString()}")
            trafficSelectorData += individualTrafficSelectorData
        }
        log.trace("trafficSelectorData [${trafficSelectorData.size}] = ${trafficSelectorData.toUByteArray().contentToString()}")
        return trafficSelectorData
    }

    override fun unmarshal(rawData: ByteArray) {
        log.info("[TrafficSelectorResponder] unmarshal(): Start unmarshalling received bytes")
        log.trace("[TrafficSelectorResponder] unmarshal(): Payload length ${rawData.size} bytes")

        var data = rawData
        if (data.isNotEmpty()) {
            log.trace("[TrafficSelectorResponder] unmarshal(): Unmarshal 1 traffic selector")
            if (data.size < 4) {
                throw Exception("TrafficSelector: No sufficient bytes to get number of traffic selector in header")
            }
            var numberOfSPI = data[0]
            data = data.drop(4).toByteArray()
            while (numberOfSPI > 0) {
                if (data.size < 4) {
                    throw Exception("TrafficSelector: No sufficient bytes to decode next individual traffic selector length in header")
                }
                val trafficSelectorType = data[0]
                if (trafficSelectorType.toUByte() == TS_IPV4_ADDR_RANGE) {
                    val selectorLength = ByteBuffer.wrap(data, 2, 2).order(ByteOrder.BIG_ENDIAN).short
                    if (selectorLength != 16.toShort()) {
                        throw Exception("TrafficSelector: A TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes")
                    }
                    if (data.size < selectorLength) {
                        throw Exception("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
                    }
                    val individualTrafficSelector = IndividualTrafficSelector()
                    individualTrafficSelector.tsType = data[0].toUByte()
                    individualTrafficSelector.ipProtocolID = data[1].toUByte()
                    individualTrafficSelector.startPort = ByteBuffer.wrap(data, 4, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
                    individualTrafficSelector.endPort = ByteBuffer.wrap(data, 6, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
                    individualTrafficSelector.startAddress += data.sliceArray(8..11)
                    individualTrafficSelector.endAddress += data.sliceArray(12..15)
                    trafficSelectors.add(individualTrafficSelector)
                    data = data.drop(16).toByteArray()
                } else if (trafficSelectorType.toUByte() == TS_IPV6_ADDR_RANGE) {
                    val selectorLength = ByteBuffer.wrap(data, 2, 2).order(ByteOrder.BIG_ENDIAN).short
                    if (selectorLength != 40.toShort()) {
                        throw Exception("TrafficSelector: A TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes")
                    }
                    if (data.size < selectorLength) {
                        throw Exception("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
                    }
                    val individualTrafficSelector = IndividualTrafficSelector()
                    individualTrafficSelector.tsType = data[0].toUByte()
                    individualTrafficSelector.ipProtocolID = data[1].toUByte()
                    individualTrafficSelector.startPort = ByteBuffer.wrap(data, 4, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
                    individualTrafficSelector.endPort = ByteBuffer.wrap(data, 6, 2).order(ByteOrder.BIG_ENDIAN).short.toUShort()
                    individualTrafficSelector.startAddress += data.sliceArray(8..23)
                    individualTrafficSelector.endAddress += data.sliceArray(24..39)
                    trafficSelectors.add(individualTrafficSelector)
                    data = data.drop(40).toByteArray()
                } else {
                    throw Exception("TrafficSelector: Unsupported traffic selector type")
                }
                numberOfSPI--
            }
        }
    }
}