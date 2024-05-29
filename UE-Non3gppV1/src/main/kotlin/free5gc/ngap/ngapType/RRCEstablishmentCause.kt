package free5gc.ngap.ngapType

enum class RRCEstablishmentCause(val value: Int) {
    Emergency(0),
    HighPriorityAccess(1),
    MtAccess(2),
    MoSignalling(3),
    MoData(4),
    MoVoiceCall(5),
    MoVideoCall(6),
    MoSMS(7),
    MpsPriorityAccess(8),
    McsPriorityAccess(9),
    NotAvailable(10)
}

