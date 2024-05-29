package engine.exchange.pkg.context

import engine.exchange.pkg.ike.message.*
import go.net.IP
import go.net.IPNet
import java.net.InetAddress
import java.net.InetSocketAddress

const val AmfUeNgapIdUnspecified: Long = 0xffffffffff

class N3iwfUe {
    var ranUeNgapId: Long = 0
    var amfUeNgapId: Long = AmfUeNgapIdUnspecified
    var iPAddrV4: String = ""
    var iPAddrV6: String = ""
    var portNumber: Int = 0
    var maskedIMEISV: free5gc.ngap.ngapType.MaskedIMEISV? = null
    var guti: String = ""
    var ipSecInnerIP: InetAddress? = null
    var ipSecInnerIPAddr: InetAddress? = null
    var amf: N3IWFAMF? = null
    var pduSessionList: MutableMap<Long, PduSession> = mutableMapOf()
    var temporaryPduSessionSetupData: PduSessionSetupTemporaryData? = nothing()
    var temporaryCachedNasMessage: ByteArray = byteArrayOf()
    var kn3iwf: UByteArray = ubyteArrayOf()
    var securityCapabilities: free5gc.ngap.ngapType.UESecurityCapabilities? = null
    var n3iwfIkeSecurityAssociation: IkeSecurityAssociation? = null
    var n3iwfChildSecurityAssociation: MutableMap<ULong, ChildSecurityAssociation> = mutableMapOf()
    var signallingIPsecSAEstablished: Boolean = false
    var temporaryExchangeMsgIDChildSAMapping: MutableMap<ULong, ChildSecurityAssociation> = mutableMapOf()
    var ikeConnection: UdpSocketInfo? = null
    var tcpConnection: java.net.Socket? = null
    var guami: free5gc.ngap.ngapType.GUAMI? = null
    var indexToRfsp: Long = 0
    var ambr: free5gc.ngap.ngapType.UEAggregateMaximumBitRate? = null
    var allowedNssai: free5gc.ngap.ngapType.AllowedNSSAI? = null
    var radioCapability: free5gc.ngap.ngapType.UERadioCapability? = null
    var coreNetworkAssistanceInformation: free5gc.ngap.ngapType.CoreNetworkAssistanceInformation? = null
    var imsVoiceSupported: Int = 0
    var rrcEstablishmentCause: Short = 0


    fun init(ranUeNgapId: Long) {
        this.ranUeNgapId = ranUeNgapId
        amfUeNgapId = AmfUeNgapIdUnspecified
        pduSessionList = mutableMapOf()
        n3iwfChildSecurityAssociation = mutableMapOf()
        temporaryExchangeMsgIDChildSAMapping = mutableMapOf()
    }

    fun remove() {
        detachAMF()

        val n3iwfSelf = N3iwfContext.self()
        n3iwfSelf.deleteN3iwfUe(ranUeNgapId)
        n3iwfSelf.deleteIkeSecurityAssociation(n3iwfIkeSecurityAssociation!!.localSPI)
        n3iwfSelf.deleteInternalUEIPAddr(ipSecInnerIP!!.toString())
        for (pduSession in pduSessionList.values) {
            n3iwfSelf.deleteTeid(pduSession.gtpConnection!!.incomingTeid)
        }
    }

    fun findPDUSession(pduSessionID: Long): PduSession? {
        return pduSessionList[pduSessionID]
    }

    fun createPDUSession(pduSessionID: Long, snssai: free5gc.ngap.ngapType.SNSSAI): PduSession? {
        if (pduSessionList.containsKey(pduSessionID)) {
            throw Exception("PDU Session[ID:$pduSessionID] is already exists")
        }
        val pduSession = PduSession()
        pduSession.id = pduSessionID
        pduSession.snssai = snssai
        pduSessionList[pduSessionID] = pduSession
        return pduSession
    }

    fun createHalfChildSA(msgID: UInt, inboundSPI: UInt) {
        val childSA = ChildSecurityAssociation()
        childSA.inboundSpi = inboundSPI
        childSA.thisUe = this
        temporaryExchangeMsgIDChildSAMapping[msgID.toULong()] = childSA
    }

    fun completeChildSA(msgID: UInt, outboundSPI: UInt, chosenSecurityAssociation: SecurityAssociation?): ChildSecurityAssociation? {
        val childSA = temporaryExchangeMsgIDChildSAMapping[msgID.toULong()]
            ?: throw Exception("There's not a half child SA created by the exchange with message ID $msgID.")
        temporaryExchangeMsgIDChildSAMapping.remove(msgID.toULong())
        if (chosenSecurityAssociation == null) {
            throw Exception("chosenSecurityAssociation is null")
        }
        if (chosenSecurityAssociation.proposals.isEmpty()) {
            throw Exception("No proposal")
        }
        childSA.outboundSpi = outboundSPI
        if (chosenSecurityAssociation.proposals[0].encryptionAlgorithm.transforms.isNotEmpty()) {
            childSA.encryptionAlgorithm = chosenSecurityAssociation.proposals[0].encryptionAlgorithm.transforms[0].transformID
        }
        if (chosenSecurityAssociation.proposals[0].integrityAlgorithm.transforms.isNotEmpty()) {
            childSA.integrityAlgorithm = chosenSecurityAssociation.proposals[0].integrityAlgorithm.transforms[0].transformID
        }
        if (chosenSecurityAssociation.proposals[0].extendedSequenceNumbers.transforms.isNotEmpty()) {
            childSA.esn = chosenSecurityAssociation.proposals[0].extendedSequenceNumbers.transforms[0].transformID.toInt() != 0
        }
        n3iwfChildSecurityAssociation[childSA.inboundSpi.toULong()] = childSA
        val n3iwfContext = N3iwfContext.self()
        n3iwfContext.childSa[childSA.inboundSpi] = childSA
        return childSA
    }

    fun attachAMF(sctpAddr: String): Boolean {
        val n3iwfContext = N3iwfContext.self()
        val amfPair = n3iwfContext.amfPoolLoad(sctpAddr)
        val n3iwfAMF = amfPair.first
        if (n3iwfAMF != null) {
            n3iwfAMF.n3iwfUeList[ranUeNgapId] = this
            amf = n3iwfAMF
            return true
        } else {
            return false
        }
    }

    fun detachAMF() {
        if (amf == null) {
            return
        }
        amf?.n3iwfUeList?.remove(ranUeNgapId)
    }

    private fun nothing() = null
}

class PduSession {
    var id: Long = 0
    var type: free5gc.ngap.ngapType.PDUSessionType? = null
    var ambr: free5gc.ngap.ngapType.PDUSessionAggregateMaximumBitRate? = null
    var snssai: free5gc.ngap.ngapType.SNSSAI? = null
    var networkInstance: free5gc.ngap.ngapType.NetworkInstance? = null
    var securityCipher: Boolean = false
    var securityIntegrity: Boolean = false
    var maximumIntegrityDataRateUplink: free5gc.ngap.ngapType.MaximumIntegrityProtectedDataRate? = null
    var maximumIntegrityDataRateDownlink: free5gc.ngap.ngapType.MaximumIntegrityProtectedDataRate? = null
    var gtpConnection: GtpConnectionInfo? = null
    var qfiList: List<UByte> = listOf()
    var qosFlows: MutableMap<Long, QosFlow> = mutableMapOf()
}

class PduSessionSetupTemporaryData {
    var unactivatedPDUSession: List<Long> = listOf()
    var ngapProcedureCode: free5gc.ngap.ngapType.ProcedureCode? = null
    var setupListCxtRes: free5gc.ngap.ngapType.PDUSessionResourceSetupListCxtRes? = null
    var failedListCxtRes: free5gc.ngap.ngapType.PDUSessionResourceFailedToSetupListCxtRes? = null
    var setupListSURes: free5gc.ngap.ngapType.PDUSessionResourceSetupListSURes? = null
    var failedListSURes: free5gc.ngap.ngapType.PDUSessionResourceFailedToSetupListSURes? = null
}

class QosFlow(val identifier: Long, val parameters: free5gc.ngap.ngapType.QosFlowLevelQosParameters)

class GtpConnectionInfo {
    var upfIpAddr: String = ""
    var upfUdpAddr: InetSocketAddress? = null
    var incomingTeid: UInt = 0u
    var otgoingTeid: UInt = 0u
    var userPlaneConnection: UPlaneConn? = null
}

class IkeSecurityAssociation {
    var remoteSPI: ULong = 0u
    var localSPI: ULong = 0u
    var initiatorMessageID: UInt = 0u
    var responderMessageID: UInt = 0u
    var encryptionAlgorithm: Transform? = null
    var pseudorandomFunction: Transform? = null
    var integrityAlgorithm: Transform? = null
    var diffieHellmanGroup: Transform? = null
    var expandedSequenceNumber: Transform? = null
    var concatenatedNonce: ByteArray = byteArrayOf()
    var diffieHellmanSharedKey: ByteArray = byteArrayOf()
    var skD: ByteArray = byteArrayOf()
    var skAi: ByteArray = byteArrayOf()
    var skAr: ByteArray = byteArrayOf()
    var skEi: ByteArray = byteArrayOf()
    var skEr: ByteArray = byteArrayOf()
    var skPi: ByteArray = byteArrayOf()
    var skPr: ByteArray = byteArrayOf()
    var state: UByte = 0u
    var initiatorID: IdentificationInitiator? = null
    var initiatorCertificate: Certificate? = null
    var ikeAuthResponseSA: SecurityAssociation? = null
    var trafficSelectorInitiator: TrafficSelectorInitiator? = null
    var trafficSelectorResponder: TrafficSelectorResponder? = null
    var lastEapIdentifier: Byte = 0
    var localUnsignedAuthentication: ByteArray = byteArrayOf()
    var remoteUnsignedAuthentication: ByteArray = byteArrayOf()
    var uEIsBehindNAT: Boolean = false
    var n3iwfIsBehindNAT: Boolean = false
    var thisUE: N3iwfUe? = null
}

class ChildSecurityAssociation {
    var inboundSpi: UInt = 0u
    var outboundSpi: UInt = 0u
    var peerPublicIpAddr: IP? = null
    var localPublicIpAddr: IP? = null
    var selectedIpProtocol: UByte = 0u
    var trafficSelectorLocal: IPNet? = null
    var trafficSelectorRemote: IPNet? = null
    var encryptionAlgorithm: UShort = 0u
    var initiatorToResponderEncryptionKey: ByteArray = byteArrayOf()
    var responderToInitiatorEncryptionKey: ByteArray = byteArrayOf()
    var integrityAlgorithm: UShort = 0u
    var initiatorToResponderIntegrityKey: ByteArray = byteArrayOf()
    var responderToInitiatorIntegrityKey: ByteArray = byteArrayOf()
    var esn: Boolean = false
    var enableEncapsulate: Boolean = false
    var n3iwfPort: Int = 0
    var natPort: Int = 0
    var thisUe: N3iwfUe? = null
}

class UdpSocketInfo {
    var conn: java.net.DatagramSocket? = null
    var n3iwfAddr: InetSocketAddress? = null
    var ueAddr: InetSocketAddress? = null
}