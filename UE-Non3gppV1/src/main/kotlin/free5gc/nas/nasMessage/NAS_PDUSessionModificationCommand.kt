package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionModificationCommand {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONMODIFICATIONCOMMANDMessageIdentity: PDUSESSIONMODIFICATIONCOMMANDMessageIdentity = PDUSESSIONMODIFICATIONCOMMANDMessageIdentity()
    var cause5GSM: Cause5GSM? = null
    var sessionAMBR: SessionAMBR? = null
    var rQTimerValue: RQTimerValue? = null
    var alwaysonPDUSessionIndication: AlwaysonPDUSessionIndication? = null
    var authorizedQosRules: AuthorizedQosRules? = null
    var mappedEPSBearerContexts: MappedEPSBearerContexts? = null
    var authorizedQosFlowDescriptions: AuthorizedQosFlowDescriptions? = null
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null

    fun encodePDUSessionModificationCommand(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONMODIFICATIONCOMMANDMessageIdentity.octet.toByte())

        cause5GSM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        sessionAMBR?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        rQTimerValue?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        alwaysonPDUSessionIndication?.let {
            buffer.put(it.octet.toByte())
        }
        authorizedQosRules?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        mappedEPSBearerContexts?.let {
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
    }

    fun decodePDUSessionModificationCommand(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONMODIFICATIONCOMMANDMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                PDUSessionModificationCommandCause5GSMType -> {
                    cause5GSM = Cause5GSM.newCause5GSM(ieiN.toUByte())
                    cause5GSM!!.octet = buffer.get().toUByte()
                }

                PDUSessionModificationCommandSessionAMBRType -> {
                    sessionAMBR = SessionAMBR.newSessionAMBR(ieiN.toUByte())
                    sessionAMBR!!.setLen(buffer.get().toUByte())

                    val auxBuffer = ByteArray(sessionAMBR!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    sessionAMBR!!.octet = auxBuffer.toUByteArray()

                }

                PDUSessionModificationCommandRQTimerValueType -> {
                    rQTimerValue = RQTimerValue.newRQTimerValue(ieiN.toUByte())
                    rQTimerValue!!.octet = buffer.get().toUByte()
                }

                PDUSessionModificationCommandAlwaysonPDUSessionIndicationType -> {
                    alwaysonPDUSessionIndication = AlwaysonPDUSessionIndication.newAlwaysonPDUSessionIndication(ieiN.toUByte())
                    alwaysonPDUSessionIndication!!.octet = ieiN.toUByte()
                }

                PDUSessionModificationCommandAuthorizedQosRulesType -> {
                    authorizedQosRules = AuthorizedQosRules.newAuthorizedQosRules(ieiN.toUByte())
                    authorizedQosRules!!.setLen(buffer.short.toUShort())

                    val auxBuffer = ByteArray(authorizedQosRules!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    authorizedQosRules!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionModificationCommandMappedEPSBearerContextsType -> {
                    mappedEPSBearerContexts = MappedEPSBearerContexts.newMappedEPSBearerContexts(ieiN.toUByte())
                    mappedEPSBearerContexts!!.setLen(buffer.short.toUShort())

                    val auxBuffer = ByteArray(mappedEPSBearerContexts!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    mappedEPSBearerContexts!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionModificationCommandAuthorizedQosFlowDescriptionsType -> {
                    authorizedQosFlowDescriptions = AuthorizedQosFlowDescriptions.newAuthorizedQosFlowDescriptions(ieiN.toUByte())
                    authorizedQosFlowDescriptions!!.setLen(buffer.short.toUShort())

                    val auxBuffer = ByteArray(authorizedQosFlowDescriptions!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    authorizedQosFlowDescriptions!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionModificationCommandExtendedProtocolConfigurationOptionsType -> {
                    extendedProtocolConfigurationOptions = ExtendedProtocolConfigurationOptions.newExtendedProtocolConfigurationOptions(ieiN.toUByte())
                    extendedProtocolConfigurationOptions!!.setLen(buffer.short.toUShort())

                    val auxBuffer = ByteArray(extendedProtocolConfigurationOptions!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    extendedProtocolConfigurationOptions!!.buffer = auxBuffer.toUByteArray()
                }

                else -> {
                }
            }
        }
    }

    companion object {
        fun newPDUSessionModificationCommand(iei: UByte): PDUSessionModificationCommand {
            return PDUSessionModificationCommand()
        }

        const val PDUSessionModificationCommandCause5GSMType: UByte = 0x59u
        const val PDUSessionModificationCommandSessionAMBRType: UByte = 0x2Au
        const val PDUSessionModificationCommandRQTimerValueType: UByte = 0x56u
        const val PDUSessionModificationCommandAlwaysonPDUSessionIndicationType: UByte = 0x08u
        const val PDUSessionModificationCommandAuthorizedQosRulesType: UByte = 0x7Au
        const val PDUSessionModificationCommandMappedEPSBearerContextsType: UByte = 0x7Fu
        const val PDUSessionModificationCommandAuthorizedQosFlowDescriptionsType: UByte = 0x79u
        const val PDUSessionModificationCommandExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu
    }
}