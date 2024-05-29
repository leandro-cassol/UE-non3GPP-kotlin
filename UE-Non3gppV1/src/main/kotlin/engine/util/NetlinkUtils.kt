package engine.util

import config.Config
import engine.exchange.pkg.context.IkeSecurityAssociation
import engine.exchange.pkg.ike.message.*
import org.slf4j.LoggerFactory
import java.net.*

class NetlinkUtils {
    private val log = LoggerFactory.getLogger(NetlinkUtils::class.java)

    fun getLinkGRE(cfg: Config): NetworkInterface {
        val links = NetworkInterface.getNetworkInterfaces().toList()
        var linkGRE: NetworkInterface? = null
        for (link in links) {
            if (link.name == cfg.ue.linkGRE.name) {
                linkGRE = link
                break
            }
        }
        return linkGRE ?: throw IllegalStateException("GRE link not found")
    }

    fun createN3IWFSecurityAssociation(
        proposal: Proposal,
        udpConnection: DatagramSocket,
        n3iwfUDPAddrIP: InetAddress,
        n3iwfUDPAddrPort: String,
        ikeMessage: IKEMessage
    ): IkeSecurityAssociation {
        val (secret, factor, localNonce, ikeMessageData) = buildInitIKEMessageData(ikeMessage)

        udpConnection.send(
            DatagramPacket(
                ikeMessageData,
                ikeMessageData.size,
                n3iwfUDPAddrIP,
                n3iwfUDPAddrPort.toInt()
            )
        )

        val buffer = ByteArray(65535)
        val packet = DatagramPacket(buffer, buffer.size)
        udpConnection.receive(packet)

        ikeMessage.payloads.reset()
        ikeMessage.decode(packet.data.copyOf(packet.length))

        var sharedKeyExchangeData = ByteArray(0)
        var remoteNonce = ByteArray(0)

        for (ikePayload in ikeMessage.payloads) {
            if (ikePayload.type() == IKEPayloadType.TypeSA) {
                log.info("Get SA payload")
            } else if (ikePayload.type() == IKEPayloadType.TypeKE) {
                val remotePublicKeyExchangeValue = (ikePayload as KeyExchange).keyExchangeData
                val remotePublicKeyExchangeValueBig = remotePublicKeyExchangeValue.removeZero().toBigInteger()
                sharedKeyExchangeData = remotePublicKeyExchangeValueBig.modPow(secret, factor).toByteArray()
                sharedKeyExchangeData = sharedKeyExchangeData.removeZero()
            } else if (ikePayload.type() == IKEPayloadType.TypeNiNr) {
                remoteNonce = (ikePayload as Nonce).nonceData
            }
        }
        val ikeSecurityAssociation = IkeSecurityAssociation()
        ikeSecurityAssociation.localSPI = createIKEInitiatorSPI()
        ikeSecurityAssociation.remoteSPI = ikeMessage.responderSPI
        ikeSecurityAssociation.initiatorMessageID = 0u
        ikeSecurityAssociation.responderMessageID = 0u
        ikeSecurityAssociation.encryptionAlgorithm = proposal.encryptionAlgorithm.transforms[0]
        ikeSecurityAssociation.integrityAlgorithm = proposal.integrityAlgorithm.transforms[0]
        ikeSecurityAssociation.pseudorandomFunction = proposal.pseudorandomFunction.transforms[0]
        ikeSecurityAssociation.diffieHellmanGroup = proposal.diffieHellmanGroup.transforms[0]
        ikeSecurityAssociation.concatenatedNonce = localNonce + remoteNonce
        ikeSecurityAssociation.diffieHellmanSharedKey = sharedKeyExchangeData

        try {
            generateKeyForIKESA(ikeSecurityAssociation)
        } catch (e: Exception) {
            log.error(e.message)
            throw Exception("Generate key for IKE SA failed")
        }
        return ikeSecurityAssociation
    }


    fun isNetworkInterfaceAvailable(interfaceName: String): Boolean {
        try {
            val networkInterface = NetworkInterface.getByName(interfaceName)
            return networkInterface != null && networkInterface.isUp
        } catch (e: SocketException) {
            return false
        }
    }

    // Adiciona um endereço IP à interface de rede especificada
    // Este comando configura dinamicamente um endereço IP na interface especificada,
    // permitindo que a máquina se comunique na rede usando esse endereço.
    fun addIpAddressToNetworkInterface(interfaceName: String, ipAddress: String, mask: String) {
        var command = ""
        if (mask.isEmpty()) {
            command = "ip addr add $ipAddress dev $interfaceName"
        } else {
            command = "ip addr add $ipAddress brd $mask dev $interfaceName"
        }
        EnvironmentSetting().executeCommand(command)
    }

    fun addIpLinkGRE(linkGRE: String, ipLocal: String, ipRemoto: String, ikey: Long, okey: Long) {
        var command = "ip link add $linkGRE type gre remote $ipRemoto local $ipLocal ikey $ikey okey $okey"
        EnvironmentSetting().executeCommand(command)

        command = "ip link set $linkGRE mtu 1452"
        EnvironmentSetting().executeCommand(command)
    }

    fun upLinkInterface(linkInterfaceName: String) {
        val command = "ip link set $linkInterfaceName up"
        EnvironmentSetting().executeCommand(command)
    }

    fun addIpRoute(interfaceName: String, ipLocal: String, ipRoute: String, table: Int) {
        val command = "ip route add $ipRoute dev $interfaceName proto kernel scope link src $ipLocal table $table"
        EnvironmentSetting().executeCommand(command)
    }
}