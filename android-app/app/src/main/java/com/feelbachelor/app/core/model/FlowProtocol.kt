package com.feelbachelor.app.core.model

enum class FlowProtocol(val code: Int) {
    TCP(6),
    UDP(17),
    ICMP(1),
    UNKNOWN(0);

    companion object {
        fun fromCode(code: Int): FlowProtocol = when (code) {
            6 -> TCP
            17 -> UDP
            1 -> ICMP
            else -> UNKNOWN
        }
    }
}
