package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionEstablishmentAccept {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONESTABLISHMENTACCEPTMessageIdentity: PDUSESSIONESTABLISHMENTACCEPTMessageIdentity = PDUSESSIONESTABLISHMENTACCEPTMessageIdentity()
    var selectedSSCModeAndSelectedPDUSessionType: SelectedSSCModeAndSelectedPDUSessionType = SelectedSSCModeAndSelectedPDUSessionType()
    var authorizedQosRules: AuthorizedQosRules = AuthorizedQosRules()
    var sessionAMBR: SessionAMBR = SessionAMBR()
    var cause5GSM: Cause5GSM? = null
    var pduAddress: PDUAddress? = null
    var rQTimerValue: RQTimerValue? = null
    var sNSSAI: SNSSAI? = null
    var alwaysonPDUSessionIndication: AlwaysonPDUSessionIndication? = null
    var mappedEPSBearerContexts: MappedEPSBearerContexts? = null
    var eapMessage: EAPMessage? = null
    var authorizedQosFlowDescriptions: AuthorizedQosFlowDescriptions? = null
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null
    var dnn: DNN? = null

    fun encodePDUSessionEstablishmentAccept(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)

        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONESTABLISHMENTACCEPTMessageIdentity.octet.toByte())
        buffer.put(selectedSSCModeAndSelectedPDUSessionType.octet.toByte())

        buffer.put(authorizedQosRules.getLen().toByte())
        buffer.put(authorizedQosRules.buffer.toByteArray(), 0, authorizedQosRules.getLen().toInt())

        buffer.put(sessionAMBR.getLen().toByte())
        buffer.put(sessionAMBR.octet.toByteArray(), 0, sessionAMBR.getLen().toInt())

        cause5GSM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        pduAddress?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        rQTimerValue?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        sNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        alwaysonPDUSessionIndication?.let {
            buffer.put(it.octet.toByte())
        }
        mappedEPSBearerContexts?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        authorizedQosFlowDescriptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        extendedProtocolConfigurationOptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        dnn?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodePDUSessionEstablishmentAccept(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONESTABLISHMENTACCEPTMessageIdentity.octet = buffer.get().toUByte()
        selectedSSCModeAndSelectedPDUSessionType.octet = buffer.get().toUByte()

        authorizedQosRules.setLen(buffer.short.toUShort())
        val auxBuffer = ByteArray(authorizedQosRules.getLen().toInt())
        buffer.get(auxBuffer)
        authorizedQosRules.buffer = auxBuffer.toUByteArray()

        sessionAMBR.setLen(buffer.get().toUByte())
        val sessionOctets = ByteArray(sessionAMBR.getLen().toInt())
        buffer.get(sessionOctets)
        sessionAMBR.octet = sessionOctets.toUByteArray()

        while (buffer.hasRemaining()) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toByte()) {
                PDUSessionEstablishmentAcceptCause5GSMType -> {
                    cause5GSM = Cause5GSM.newCause5GSM(ieiN.toUByte())
                    cause5GSM!!.octet = buffer.get().toUByte()
                }

                PDUSessionEstablishmentAcceptPDUAddressType -> {
                    pduAddress = PDUAddress.newPDUAddress(ieiN.toUByte())
                    val auxLen = pduAddress!!.octet.size
                    pduAddress!!.setLen(auxLen.toUByte())

                    val auxBuffer = ByteArray(pduAddress!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    pduAddress!!.octet = auxBuffer.toUByteArray()
                }

                PDUSessionEstablishmentAcceptRQTimerValueType -> {
                    rQTimerValue = RQTimerValue.newRQTimerValue(ieiN.toUByte())
                    rQTimerValue!!.octet = buffer.get().toUByte()
                }

                PDUSessionEstablishmentAcceptSNSSAIType -> {
                    sNSSAI = SNSSAI.newSNSSAI(ieiN.toUByte())
                    sNSSAI!!.setLen(buffer.get().toUByte())

                    val auxBuffer = ByteArray(sNSSAI!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    sNSSAI!!.octet = auxBuffer.toUByteArray()
                }

                PDUSessionEstablishmentAcceptAlwaysonPDUSessionIndicationType -> {
                    alwaysonPDUSessionIndication = AlwaysonPDUSessionIndication.newAlwaysonPDUSessionIndication(ieiN.toUByte())
                    alwaysonPDUSessionIndication!!.octet = buffer.get().toUByte()
                }

                PDUSessionEstablishmentAcceptMappedEPSBearerContextsType -> {
                    mappedEPSBearerContexts = MappedEPSBearerContexts.newMappedEPSBearerContexts(ieiN.toUByte())
                    mappedEPSBearerContexts!!.setLen(buffer.short.toUShort())
                    val auxBuffer = ByteArray(mappedEPSBearerContexts!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    mappedEPSBearerContexts!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionEstablishmentAcceptEAPMessageType -> {
                    eapMessage = EAPMessage.newEAPMessage(ieiN.toUByte())
                    eapMessage!!.setLen(buffer.short.toUShort())
                    val eapBuffer = ByteArray(eapMessage!!.getLen().toInt())
                    buffer.get(eapBuffer)
                    eapMessage!!.buffer = eapBuffer.toUByteArray()
                }

                PDUSessionEstablishmentAcceptAuthorizedQosFlowDescriptionsType -> {
                    authorizedQosFlowDescriptions = AuthorizedQosFlowDescriptions.newAuthorizedQosFlowDescriptions(ieiN.toUByte())
                    authorizedQosFlowDescriptions!!.setLen(buffer.short.toUShort())
                    val auxBuffer = ByteArray(authorizedQosFlowDescriptions!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    authorizedQosFlowDescriptions!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionEstablishmentAcceptExtendedProtocolConfigurationOptionsType -> {
                    extendedProtocolConfigurationOptions = ExtendedProtocolConfigurationOptions.newExtendedProtocolConfigurationOptions(ieiN.toUByte())
                    extendedProtocolConfigurationOptions!!.setLen(buffer.short.toUShort())
                    val auxBuffer = ByteArray(extendedProtocolConfigurationOptions!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    extendedProtocolConfigurationOptions!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionEstablishmentAcceptDNNType -> {
                    dnn = DNN.newDNN(ieiN.toUByte())
                    dnn!!.setLen(buffer.get().toUByte())

                    val auxBuffer = ByteArray(dnn!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    dnn!!.buffer = auxBuffer.toUByteArray()
                }

                else -> {
                }
            }
        }
    }

    companion object {
        fun newPDUSessionEstablishmentAccept(iei: UByte): PDUSessionEstablishmentAccept {
            return PDUSessionEstablishmentAccept()
        }

        const val PDUSessionEstablishmentAcceptCause5GSMType: Byte = 0x59
        const val PDUSessionEstablishmentAcceptPDUAddressType: Byte = 0x29
        const val PDUSessionEstablishmentAcceptRQTimerValueType: Byte = 0x56
        const val PDUSessionEstablishmentAcceptSNSSAIType: Byte = 0x22
        const val PDUSessionEstablishmentAcceptAlwaysonPDUSessionIndicationType: Byte = 0x08
        const val PDUSessionEstablishmentAcceptMappedEPSBearerContextsType: Byte = 0x75
        const val PDUSessionEstablishmentAcceptEAPMessageType: Byte = 0x78
        const val PDUSessionEstablishmentAcceptAuthorizedQosFlowDescriptionsType: Byte = 0x79
        const val PDUSessionEstablishmentAcceptExtendedProtocolConfigurationOptionsType: Byte = 0x7B
        const val PDUSessionEstablishmentAcceptDNNType: Byte = 0x25
    }
}