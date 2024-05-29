package engine.exchange.pkg.context

import free5gc.util.idgenerator.IDGenerator
import go.net.*
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap
import kotlin.collections.set

private val log = LoggerFactory.getLogger("Context")



class N3iwfContext {
    var nfInfo: N3iwfNfInfo? = null
    var amfSctpAddresses: MutableList<SCTPAddr> = mutableListOf()

    // ID generators
    var ranUeNgapIdGenerator: IDGenerator = IDGenerator(0, Long.MAX_VALUE)
    var teIdGenerator: IDGenerator = IDGenerator(1, UInt.MAX_VALUE.toLong())

    // Pools
    var uePool: ConcurrentMap<Long, N3iwfUe> = ConcurrentHashMap()
    var amfPool: ConcurrentMap<String, N3IWFAMF> = ConcurrentHashMap()
    var amfReInitAvailableList: ConcurrentMap<String, Boolean> = ConcurrentHashMap()
    var ikeSa: ConcurrentMap<ULong, IkeSecurityAssociation> = ConcurrentHashMap()
    var childSa: ConcurrentMap<UInt, ChildSecurityAssociation> = ConcurrentHashMap()
    var gtpConnectionWithUPF: ConcurrentHashMap<String, Any> = ConcurrentHashMap()
    var allocatedUeIpAddress: ConcurrentMap<String, N3iwfUe> = ConcurrentHashMap()
    var allocatedUeTeid: ConcurrentMap<UInt, N3iwfUe> = ConcurrentHashMap()

    // N3IWF FQDN
    var fqdn: String = ""

    // Security data
    var certificateAuthority: ByteArray = byteArrayOf()
    var n3iwfCertificate: ByteArray = byteArrayOf()
    var n3iwfPrivateKey: java.security.PrivateKey? = null

    // UEIPAddressRange
    var subnet: IPNet? = null

    // Network interface mark for xfrm
    var mark: UInt = 0u

    // N3IWF local address
    var ikeBindAddress: String = ""
    var ipSecGatewayAddress: String = ""
    var gtpBindAddress: String = ""
    var tcpPort: UShort = 0u

    // N3IWF NWu interface IPv4 packet connection
    var nwuIpv4PacketConn: PacketConn? = null


    companion object {
        private val n3iwfContext = N3iwfContext()

        init {
            n3iwfContext.ranUeNgapIdGenerator = IDGenerator(0, Long.MAX_VALUE)
            n3iwfContext.teIdGenerator = IDGenerator(1, UInt.MAX_VALUE.toLong())
        }

        fun self(): N3iwfContext {
            return n3iwfContext
        }
    }

    fun newN3iwfUe(): N3iwfUe? {
        val ranUeNgapId: Long
        try {
            ranUeNgapId = ranUeNgapIdGenerator.allocate()
        } catch (e: Exception) {
            log.error("New N3IWF UE failed: $e")
            return null
        }
        val n3iwfUe = N3iwfUe()
        n3iwfUe.init(ranUeNgapId)
        uePool[ranUeNgapId] = n3iwfUe
        return n3iwfUe
    }

    fun deleteN3iwfUe(ranUeNgapId: Long) {
        uePool.remove(ranUeNgapId)
    }

    fun uePoolLoad(ranUeNgapId: Long): Pair<N3iwfUe?, Boolean> {
        val ue = uePool[ranUeNgapId]
        return Pair(ue, ue != null)
    }

    fun newN3iwfAmf(sctpAddr: String, conn: SCTPConn): N3IWFAMF {
        val amf = N3IWFAMF()
        amf.init(sctpAddr, conn)
        val item = amfPool.putIfAbsent(sctpAddr, amf)
        if (item != null) {
            log.warn("[Context] NewN3iwfAmf(): AMF entry already exists.")
            return item
        }
        return amf
    }

    fun deleteN3iwfAmf(sctpAddr: String) {
        amfPool.remove(sctpAddr)
    }

    fun amfPoolLoad(sctpAddr: String): Pair<N3IWFAMF?, Boolean> {
        val amf = amfPool[sctpAddr]
        return Pair(amf, amf != null)
    }

    fun deleteAmfReInitAvailableFlag(sctpAddr: String) {
        amfReInitAvailableList.remove(sctpAddr)
    }

    fun amfReInitAvailableListLoad(sctpAddr: String): Pair<Boolean, Boolean> {
        val result = amfReInitAvailableList[sctpAddr]
        return if (result != null) {
            Pair(result, true)
        } else {
            Pair(true, false)
        }
    }

    fun amfReInitAvailableListStore(sctpAddr: String, flag: Boolean) {
        amfReInitAvailableList[sctpAddr] = flag
    }

    fun newIkeSecurityAssociation(): IkeSecurityAssociation? {
        val ikeSecurityAssociation = IkeSecurityAssociation()
        val maxSPI = BigInteger.valueOf(Long.MAX_VALUE)
        var localSPI: BigInteger
        var localSPIuint64: ULong
        while (true) {
            try {
                localSPI = BigInteger(maxSPI.bitLength(), SecureRandom())
            } catch (e: Exception) {
                log.error("[Context] Error occurs when generate new IKE SPI")
                return null
            }
            localSPIuint64 = localSPI.toLong().toULong()
            if (ikeSa.putIfAbsent(localSPI.toLong().toULong(), ikeSecurityAssociation) == null) {
                break
            }
        }
        ikeSecurityAssociation.localSPI = localSPIuint64
        return ikeSecurityAssociation
    }

    fun deleteIkeSecurityAssociation(spi: ULong) {
        ikeSa.remove(spi)
    }

    fun ikeSALoad(spi: ULong): Pair<IkeSecurityAssociation?, Boolean> {
        val securityAssociation = ikeSa[spi]
        return Pair(securityAssociation, securityAssociation != null)
    }

    fun deleteGTPConnection(upfAddr: String) {
        gtpConnectionWithUPF.remove(upfAddr)
    }

    fun newInternalUeIpAddr(ue: N3iwfUe): IP? {
        var ueIPAddr: IP?
        while (true) {
            ueIPAddr = engine.util.generateRandomIPInRange(subnet)
            if (ueIPAddr != null) {
                if (ueIPAddr.toString() == ipSecGatewayAddress) {
                    continue
                }
                if (allocatedUeIpAddress.putIfAbsent(ueIPAddr.toString(), ue) == null) {
                    break
                }
            }
        }
        return ueIPAddr
    }

    fun deleteInternalUEIPAddr(ipAddr: String) {
        allocatedUeIpAddress.remove(ipAddr)
    }

    fun allocatedUeIpAddressLoad(ipAddr: String): Pair<N3iwfUe?, Boolean> {
        val ue = allocatedUeIpAddress[ipAddr]
        return Pair(ue, ue != null)
    }

    fun newTeid(ue: N3iwfUe): Int {
        val teid64: Long
        try {
            teid64 = teIdGenerator.allocate()
        } catch (e: Exception) {
            log.error("New TEID failed: $e")
            return 0
        }
        val teid32 = teid64.toInt()
        allocatedUeTeid[teid32.toUInt()] = ue
        return teid32
    }

    fun deleteTeid(teid: UInt) {
        allocatedUeTeid.remove(teid)
    }

    fun allocatedUeTeidLoad(teid: UInt): Pair<N3iwfUe?, Boolean> {
        val ue = allocatedUeTeid[teid]
        return Pair(ue, ue != null)
    }

//    fun AMFSelection(ueSpecifiedGUAMI: free5gc.ngap.ngapType.GUAMI?, ueSpecifiedPLMNId: free5gc.ngap.ngapType.PLMNIdentity?): N3IWFAMF? {
//        var availableAMF: N3IWFAMF? = null
//        amfPool.forEach { _, amf ->
//            if (amf.findAvalibleAMFByCompareGUAMI(ueSpecifiedGUAMI)) {
//                availableAMF = amf
//                return@forEach
//            } else if (amf.findAvalibleAMFByCompareSelectedPLMNId(ueSpecifiedPLMNId)) {
//                availableAMF = amf
//                return@forEach
//            }
//        }
//        return availableAMF
//    }

}