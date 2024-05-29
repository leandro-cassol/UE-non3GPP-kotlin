package free5gc.nas.nasConvert

import engine.util.toByteArray
import free5gc.nas.nasMessage.CommInfoIE
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

class ProtocolOrContainerUnit {
    var protocolOrContainerID: UShort = 0u
    var lengthOfContents: UByte = 0u
    var contents: ByteArray = ByteArray(0)

    companion object {
        fun newProtocolOrContainerUnit(): ProtocolOrContainerUnit {
            return ProtocolOrContainerUnit()
        }
    }
}


class ProtocolConfigurationOptions {
    var protocolOrContainerList: MutableList<ProtocolOrContainerUnit> = mutableListOf()

    companion object {
        enum class PCOReadingState(val state: Int) {
            ReadingID(0),
            ReadingLength(1),
            ReadingContent(2)
        }

        fun newProtocolConfigurationOptions(): ProtocolConfigurationOptions {
            return ProtocolConfigurationOptions()
        }
    }


    fun marshal(): ByteArray {
        val metaInfo: Byte = (1 shl 7).toByte()
        val buffer = ByteBuffer.allocate(1024)
        buffer.put(metaInfo)
        for (containerUnit in protocolOrContainerList) {
            buffer.putShort(containerUnit.protocolOrContainerID.toShort())
            buffer.put(containerUnit.lengthOfContents.toByte())
            buffer.put(containerUnit.contents)
        }
        return buffer.flip().toByteArray()
    }

    fun unMarshal(data: ByteArray) {
        var byteReader = ByteBuffer.wrap(data)
        val metaInfo = byteReader.get()
        while (byteReader.hasRemaining()) {
            val curContainer = ProtocolOrContainerUnit()
            curContainer.protocolOrContainerID = byteReader.short.toUShort()
            curContainer.lengthOfContents = byteReader.get().toUByte()
            if (curContainer.lengthOfContents.toInt() == 0) {
                protocolOrContainerList.add(curContainer)
            } else {
                val contents = ByteArray(curContainer.lengthOfContents.toInt())
                byteReader.get(contents)
                curContainer.contents = contents
                protocolOrContainerList.add(curContainer)
            }
        }
    }

    fun addDNSServerIPv4AddressRequest() {
        val protocolOrContainerUnit = ProtocolOrContainerUnit()
        protocolOrContainerUnit.protocolOrContainerID = CommInfoIE.DNSServerIPv4AddressRequestUL
        protocolOrContainerUnit.lengthOfContents = 0u
        protocolOrContainerList.add(protocolOrContainerUnit)
    }

    fun addDNSServerIPv6AddressRequest() {
        val protocolOrContainerUnit = ProtocolOrContainerUnit()
        protocolOrContainerUnit.protocolOrContainerID = CommInfoIE.DNSServerIPv6AddressRequestUL
        protocolOrContainerUnit.lengthOfContents = 0u
        protocolOrContainerList.add(protocolOrContainerUnit)
    }

    fun ProtocolConfigurationOptions.addDNSServerIPv6Address(dnsIP: Inet6Address) {
        if (dnsIP.address.size != 16) {
            throw IllegalArgumentException("The length of DNS IPv6 is wrong!")
        }
        val protocolOrContainerUnit = ProtocolOrContainerUnit()
        protocolOrContainerUnit.protocolOrContainerID = CommInfoIE.DNSServerIPv6AddressDL
        protocolOrContainerUnit.lengthOfContents = dnsIP.address.size.toUByte()
        protocolOrContainerUnit.contents = dnsIP.address
        protocolOrContainerList.add(protocolOrContainerUnit)
    }

    fun addIPv4LinkMTU(mtu: Short) {
        val protocolOrContainerUnit = ProtocolOrContainerUnit()
        protocolOrContainerUnit.protocolOrContainerID = CommInfoIE.IPv4LinkMTUDL
        protocolOrContainerUnit.lengthOfContents = 2u
        protocolOrContainerUnit.contents = ByteBuffer.allocate(2).putShort(mtu).array()
        protocolOrContainerList.add(protocolOrContainerUnit)
    }

    fun addIPAddressAllocationViaNASSignallingUL() {
        val protocolOrContainerUnit = ProtocolOrContainerUnit()
        protocolOrContainerUnit.protocolOrContainerID = CommInfoIE.IPAddressAllocationViaNASSignallingUL
        protocolOrContainerUnit.lengthOfContents = 0u
        protocolOrContainerList.add(protocolOrContainerUnit)
    }

    fun addDNSServerIPv4Address(dnsIP: InetAddress) {
        if (dnsIP is Inet4Address) {
            val protocolOrContainerUnit = ProtocolOrContainerUnit()
            protocolOrContainerUnit.protocolOrContainerID = CommInfoIE.DNSServerIPv4AddressDL
            protocolOrContainerUnit.lengthOfContents = 4u
            protocolOrContainerUnit.contents = dnsIP.address
            protocolOrContainerList.add(protocolOrContainerUnit)
        } else {
            throw IllegalArgumentException("The DNS IP should be IPv4 in addDNSServerIPv4Address!")
        }
    }

    fun addPCSCFIPv4Address(pcscfIP: InetAddress) {
        if (pcscfIP is Inet4Address) {
            val protocolOrContainerUnit = ProtocolOrContainerUnit()
            protocolOrContainerUnit.protocolOrContainerID = CommInfoIE.PCSCFIPv4AddressDL
            protocolOrContainerUnit.lengthOfContents = 4u
            protocolOrContainerUnit.contents = pcscfIP.address
            protocolOrContainerList.add(protocolOrContainerUnit)
        } else {
            throw IllegalArgumentException("The P-CSCF IP should be IPv4!")
        }
    }
}