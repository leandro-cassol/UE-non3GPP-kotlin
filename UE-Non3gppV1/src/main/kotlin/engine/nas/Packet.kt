package engine.nas

import free5gc.nas.Message
import free5gc.nas.SecurityHeader
import free5gc.nas.nasMessage.Epd5GSMobilityManagementMessage
import engine.ran.RanUeContext
import engine.security.nasEncode


fun encodeNasPduWithSecurity(ue: RanUeContext?, pdu: ByteArray, securityHeaderType: Byte,
                             securityContextAvailable: Boolean, newSecurityContext: Boolean): ByteArray {

    val m = Message.newMessage()
    m.plainNasDecode(pdu)

    val auxSecurityHeader = SecurityHeader()
    auxSecurityHeader.protocolDiscriminator = Epd5GSMobilityManagementMessage
    auxSecurityHeader.securityHeaderType = securityHeaderType.toUByte()
    m.securityHeader = auxSecurityHeader

    return nasEncode(ue, m, securityContextAvailable, newSecurityContext)
}
