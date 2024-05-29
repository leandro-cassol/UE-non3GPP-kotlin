package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class SecurityModeCommand {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var securityModeCommandMessageIdentity: SecurityModeCommandMessageIdentity = SecurityModeCommandMessageIdentity()
    var selectedNASSecurityAlgorithms: SelectedNASSecurityAlgorithms = SelectedNASSecurityAlgorithms()
    var spareHalfOctetAndNgksi: SpareHalfOctetAndNgksi = SpareHalfOctetAndNgksi()
    var replayedUESecurityCapabilities: ReplayedUESecurityCapabilities = ReplayedUESecurityCapabilities()
    var imeisvRequest: IMEISVRequest? = null
    var selectedEPSNASSecurityAlgorithms: SelectedEPSNASSecurityAlgorithms? = null
    var additional5GSecurityInformation: Additional5GSecurityInformation? = null
    var eapMessage: EAPMessage? = null
    var abba: ABBA? = null
    var replayedS1UESecurityCapabilities: ReplayedS1UESecurityCapabilities? = null

    companion object {
        const val SecurityModeCommandIMEISVRequestType: UByte = 0x0Eu
        const val SecurityModeCommandSelectedEPSNASSecurityAlgorithmsType: UByte = 0x57u
        const val SecurityModeCommandAdditional5GSecurityInformationType: UByte = 0x36u
        const val SecurityModeCommandEAPMessageType: UByte = 0x78u
        const val SecurityModeCommandABBAType: UByte = 0x38u
        const val SecurityModeCommandReplayedS1UESecurityCapabilitiesType: UByte = 0x19u

        fun newSecurityModeCommand(iei: UByte): SecurityModeCommand {
            return SecurityModeCommand()
        }
    }

    fun encodeSecurityModeCommand(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(securityModeCommandMessageIdentity.octet.toByte())
        buffer.put(selectedNASSecurityAlgorithms.octet.toByte())
        buffer.put(spareHalfOctetAndNgksi.octet.toByte())

        buffer.put(replayedUESecurityCapabilities.getLen().toByte())
        buffer.put(replayedUESecurityCapabilities.buffer.toByteArray())

        imeisvRequest?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        selectedEPSNASSecurityAlgorithms?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        additional5GSecurityInformation?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
        abba?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        replayedS1UESecurityCapabilities?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray())
        }
    }

    fun decodeSecurityModeCommand(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        securityModeCommandMessageIdentity.octet = buffer.get().toUByte()
        selectedNASSecurityAlgorithms.octet = buffer.get().toUByte()
        spareHalfOctetAndNgksi.octet = buffer.get().toUByte()

        replayedUESecurityCapabilities.setLen(buffer.get().toUByte())
        val replayedBuffer = ByteArray(replayedUESecurityCapabilities.getLen().toInt())
        buffer.get(replayedBuffer)
        replayedUESecurityCapabilities.buffer = replayedBuffer.toUByteArray()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                SecurityModeCommandIMEISVRequestType -> {
                    imeisvRequest = IMEISVRequest.newIMEISVRequest(ieiN.toUByte())
                    imeisvRequest!!.octet = ieiN.toUByte()
                }

                SecurityModeCommandSelectedEPSNASSecurityAlgorithmsType -> {
                    selectedEPSNASSecurityAlgorithms = SelectedEPSNASSecurityAlgorithms.newSelectedEPSNASSecurityAlgorithms(ieiN.toUByte())
                    selectedEPSNASSecurityAlgorithms!!.octet = buffer.get().toUByte()
                }

                SecurityModeCommandAdditional5GSecurityInformationType -> {
                    additional5GSecurityInformation = Additional5GSecurityInformation.newAdditional5GSecurityInformation(ieiN.toUByte())
                    additional5GSecurityInformation!!.setLen(buffer.get().toUByte())
                    additional5GSecurityInformation!!.octet = buffer.get().toUByte()
                }

                SecurityModeCommandEAPMessageType -> {
                    eapMessage = EAPMessage.newEAPMessage(ieiN.toUByte())
                    eapMessage!!.setLen(buffer.short.toUShort())
                    val eapBuffer = ByteArray(eapMessage!!.getLen().toInt())
                    buffer.get(eapBuffer)
                    eapMessage!!.buffer = eapBuffer.toUByteArray()
                }

                SecurityModeCommandABBAType -> {
                    abba = ABBA.newABBA(ieiN.toUByte())
                    abba!!.setLen(buffer.get().toUByte())
                    val abbaBuffer = ByteArray(abba!!.getLen().toInt())
                    buffer.get(abbaBuffer)
                    abba!!.buffer = abbaBuffer.toUByteArray()
                }

                SecurityModeCommandReplayedS1UESecurityCapabilitiesType -> {
                    replayedS1UESecurityCapabilities = ReplayedS1UESecurityCapabilities.newReplayedS1UESecurityCapabilities(ieiN.toUByte())
                    replayedS1UESecurityCapabilities!!.setLen(buffer.get().toUByte())
                    val rBuffer = ByteArray(replayedS1UESecurityCapabilities!!.getLen().toInt())
                    buffer.get(rBuffer)
                    replayedS1UESecurityCapabilities!!.buffer = rBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}