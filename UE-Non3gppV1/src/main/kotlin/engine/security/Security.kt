package engine.security

import engine.ran.RanUeContext
import engine.util.toUByteArrayString
import free5gc.nas.Message
import free5gc.openapi.models.AccessType
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger("Security")

fun nasEncode(ue: RanUeContext?, msg: Message?, securityContextAvailable: Boolean, newSecurityContext: Boolean): ByteArray {
    var payload: ByteArray?
    val sequenceNumber: Byte

    if (ue == null) {
        throw Exception("amfUe is nil")
    }
    if (msg == null) {
        throw Exception("Nas Message is empty")
    }
    if (!securityContextAvailable) {
        payload = msg.plainNasEncode()
        return payload!!
    } else {
        if (newSecurityContext) {
            ue.ulCount.set(0u, 0u)
            ue.dlCount.set(0u, 0u)
        }
        sequenceNumber = ue.ulCount.sqn().toByte()
        payload = msg.plainNasEncode()

        log.trace("payload [${payload!!.size}] = ${payload.toUByteArrayString()}")

        free5gc.nas.security.nasEncrypt(
            ue.cipheringAlg,
            ue.knasEnc.toByteArray(),
            ue.ulCount.get(),
            ue.getBearerType().toUByte(),
            free5gc.nas.security.DirectionUplink,
            payload
        )

        log.trace("payload [${payload.size}] = ${payload.toUByteArrayString()}")
        // add sequece number
        payload = byteArrayOf(sequenceNumber) + payload

        val mac32 = free5gc.nas.security.nasMacCalculate(
            ue.integrityAlg,
            ue.knasInt,
            ue.ulCount.get(),
            ue.getBearerByType(AccessType.AccessType_NON_3_GPP_ACCESS).toUByte(),
            free5gc.nas.security.DirectionUplink,
            payload
        )

        // Add mac value
        payload = mac32 + payload

        // Add EPD and Security Type
        val msgSecurityHeader = byteArrayOf(msg.securityHeader.protocolDiscriminator.toByte(), msg.securityHeader.securityHeaderType.toByte())
        payload = msgSecurityHeader + payload

        // Increase UL Count
        ue.ulCount.addOne()
    }
    return payload
}