package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DeregistrationRequestUETerminatedDeregistration {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var deregistrationRequestMessageIdentity: DeregistrationRequestMessageIdentity = DeregistrationRequestMessageIdentity()
    var spareHalfOctetAndDeregistrationType: SpareHalfOctetAndDeregistrationType = SpareHalfOctetAndDeregistrationType()
    var cause5GMM: Cause5GMM? = null
    var t3346Value: T3346Value? = null

    companion object {
        const val DeregistrationRequestUETerminatedDeregistrationCause5GMMType: UByte = 0x58u
        const val DeregistrationRequestUETerminatedDeregistrationT3346ValueType: UByte = 0x5Fu

        fun NewDeregistrationRequestUETerminatedDeregistration(iei: UByte): DeregistrationRequestUETerminatedDeregistration {
            return DeregistrationRequestUETerminatedDeregistration()
        }
    }

    fun encodeDeregistrationRequestUETerminatedDeregistration(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(deregistrationRequestMessageIdentity.octet.toByte())
        buffer.put(spareHalfOctetAndDeregistrationType.octet.toByte())

        cause5GMM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        t3346Value?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
    }

    fun decodeDeregistrationRequestUETerminatedDeregistration(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        deregistrationRequestMessageIdentity.octet = buffer.get().toUByte()
        spareHalfOctetAndDeregistrationType.octet = buffer.get().toUByte()

        while (buffer.hasRemaining()) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                DeregistrationRequestUETerminatedDeregistrationCause5GMMType -> {
                    cause5GMM = Cause5GMM.newCause5GMM(ieiN.toUByte())
                    cause5GMM!!.octet = buffer.get().toUByte()
                }

                DeregistrationRequestUETerminatedDeregistrationT3346ValueType -> {
                    t3346Value = T3346Value.newT3346Value(ieiN.toUByte())
                    t3346Value!!.setLen(buffer.get().toUByte())
                    t3346Value!!.octet = buffer.get().toUByte()
                }
                else -> {
                }
            }
        }
    }
}