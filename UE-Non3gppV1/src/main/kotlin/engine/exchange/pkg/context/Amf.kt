package engine.exchange.pkg.context

import free5gc.ngap.ngapType.*
import go.net.SCTPConn

class N3IWFAMF {
    var sctpAddr: String = ""
    var sctpConn: SCTPConn? = null
    var amfName: AMFName? = null
    var servedGUAMIList: ServedGUAMIList? = null
    var relativeAmfCapacity: RelativeAMFCapacity? = null
    var plmnSupportList: PLMNSupportList? = null
    var amfTnlAssociationList: MutableMap<String, AmfTnlAssociationItem> = mutableMapOf()  // v4+v6 as key
    // Overload related
    var amfOverloadContent: AmfOverloadContent? = null
    // Relative Context
    var n3iwfUeList: MutableMap<Long, N3iwfUe> = mutableMapOf()     //ranUeNgapId as key

    fun init(sctpAddr: String, conn: SCTPConn) {
        this.sctpAddr = sctpAddr
        sctpConn = conn
        amfTnlAssociationList = mutableMapOf()
        n3iwfUeList = mutableMapOf()
    }

    fun findUeByAmfUeNgapID(id: Long): N3iwfUe? {
        for (n3iwfUe in n3iwfUeList.values) {
            if (n3iwfUe.amfUeNgapId == id) {
                return n3iwfUe
            }
        }
        return null
    }

    fun removeAllRelatedUe() {
        for (ue in n3iwfUeList.values) {
            ue.remove()
        }
    }

    fun addAMFTNLAssociationItem(info: CPTransportLayerInformation): AmfTnlAssociationItem {
        val item = AmfTnlAssociationItem()
        info.endpointIPAddress?.let {
            val (ipv4, ipv6) = free5gc.ngap.ngapConvert.ipAddressToString(it)
            amfTnlAssociationList[ipv4 + ipv6]= item
        }
        return item
    }

    fun findAMFTNLAssociationItem(info: CPTransportLayerInformation): AmfTnlAssociationItem? {
        info.endpointIPAddress?.let {
            val (ipv4, ipv6) = free5gc.ngap.ngapConvert.ipAddressToString(it)
            return amfTnlAssociationList[ipv4 + ipv6]
        }
        return null
    }

    fun deleteAMFTNLAssociationItem(info: CPTransportLayerInformation) {
        info.endpointIPAddress?.let {
            val (ipv4, ipv6) = free5gc.ngap.ngapConvert.ipAddressToString(it)
            amfTnlAssociationList.remove(ipv4 + ipv6)
        }
    }

    fun startOverload(resp: OverloadResponse?, trafloadInd: TrafficLoadReductionIndication?, nssai: OverloadStartNSSAIList?): AmfOverloadContent? {
        if (resp == null && trafloadInd == null && nssai == null) {
            return null
        }
        val content = AmfOverloadContent()
        if (resp != null) {
            content.action = resp.overloadAction
        }
        if (trafloadInd != null) {
            content.trafficInd = trafloadInd.value
        }
        if (nssai != null) {
            for (item in nssai.list) {
                val sliceItem = SliceOverloadItem()
                for (item2 in item.sliceOverloadList.list) {
                    sliceItem.snssaiList.add(item2.sNSSAI)
                }
                if (item.sliceOverloadResponse != null) {
                    sliceItem.action = item.sliceOverloadResponse.overloadAction
                }
                if (item.sliceTrafficLoadReductionIndication != null) {
                    sliceItem.trafficInd = item.sliceTrafficLoadReductionIndication.value
                }
                content.nssaiList.add(sliceItem)
            }
        }
        amfOverloadContent = content
        return amfOverloadContent
    }

    fun stopOverload() {
        amfOverloadContent = null
    }

    // FindAvalibleAMFByCompareGUAMI compares the incoming GUAMI with AMF served GUAMI
    // and return if this AMF is avalible for UE
//    fun findAvalibleAMFByCompareGUAMI(ueSpecifiedGUAMI: GUAMI?): Boolean {
//        if (ueSpecifiedGUAMI == null) {
//            return false
//        }
//        val codedUESpecifiedGUAMI = free5gc.util.marshalWithParams(ueSpecifiedGUAMI, "valueExt")
//        val ueSpecifiedGUAMIByte = codedUESpecifiedGUAMI.first;
//        var erro = codedUESpecifiedGUAMI.second
//        if (erro != null) {
//            return false
//        }
//
//        for (amfServedGUAMI in ServedGUAMIList?.list ?: emptyList()) {
//            val codedAMFServedGUAMI = free5gc.util.marshalWithParams(amfServedGUAMI.GUAMI, "valueExt")
//            val amfServedGUAMIByte = codedAMFServedGUAMI.first;
//            erro = codedAMFServedGUAMI.second
//            if (erro != null) {
//                return false
//            }
//            if (!amfServedGUAMIByte.contentEquals(ueSpecifiedGUAMIByte)) {
//                continue
//            }
//            return true
//        }
//        return false
//    }

    fun findAvalibleAMFByCompareSelectedPLMNId(ueSpecifiedSelectedPLMNId: PLMNIdentity?): Boolean {
        if (ueSpecifiedSelectedPLMNId == null) {
            return false
        }

        for (amfServedPLMNId in plmnSupportList?.list ?: emptyList()) {
            if (!amfServedPLMNId.plmnIdentity.value.contentEquals(ueSpecifiedSelectedPLMNId.value)) {
                continue
            }
            return true
        }
        return false
    }
}

class AmfTnlAssociationItem {
    var ipv4: String = ""
    var ipv6: String = ""
    var tnlAssociationUsage: TNLAssociationUsage? = null
    var tnlAddressWeightFactor: Long? = null
}

class AmfOverloadContent {
    var action: OverloadAction? = null
    var trafficInd: Long? = null
    var nssaiList: MutableList<SliceOverloadItem> = mutableListOf()
}

class SliceOverloadItem {
    var snssaiList: MutableList<SNSSAI> = mutableListOf()
    var action: OverloadAction? = null
    var trafficInd: Long? = null
}
