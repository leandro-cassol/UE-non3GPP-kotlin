package free5gc.ngap.ngapType

enum class OverloadAction(val value: Int) {
    PresentRejectNonEmergencyMoDt(0),
    PresentRejectRrcCrSignalling(1),
    PermitEmergencySessionsAndMobileTerminatedServicesOnly(2),
    PermitHighPrioritySessionsAndMobileTerminatedServicesOnly(3)
}

