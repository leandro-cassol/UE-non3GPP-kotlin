package free5gc.ngap.ngapType;

enum class CauseProtocol(val value: Int) {
    PresentTransferSyntaxError(0),
    PresentAbstractSyntaxErrorReject(1),
    PresentAbstractSyntaxErrorIgnoreAndNotify(2),
    PresentMessageNotCompatibleWithReceiverState(3),
    PresentSemanticError(4),
    PresentAbstractSyntaxErrorFalselyConstructedMessage(5),
    PresentUnspecified(6);
}

