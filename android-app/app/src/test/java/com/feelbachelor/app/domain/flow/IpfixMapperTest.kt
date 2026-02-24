package com.feelbachelor.app.domain.flow

import com.feelbachelor.app.core.model.FlowProtocol
import com.feelbachelor.app.core.model.FlowRecord
import com.feelbachelor.app.core.model.IpfixMapper
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IpfixMapperTest {
    @Test
    fun `includes ipfix mapping fields in flow payload`() {
        val flow = FlowRecord(
            id = "f1",
            timestampStartMillis = 1000,
            timestampEndMillis = 2000,
            appId = "com.test",
            protocol = FlowProtocol.TCP,
            srcIp = "10.0.0.2",
            srcPort = 44444,
            dstIp = "8.8.8.8",
            dstPort = 443,
            bytesOut = 10,
            bytesIn = 20,
            packetsOut = 1,
            packetsIn = 1,
            durationMillis = 1000,
            destinationHash = "abcd1234",
            destinationNovelty = 1.0
        )

        val payload = IpfixMapper.toMobileFlowJson(flow, "device123")
        val json = JSONObject(payload)

        assertEquals(9, json.getInt("netflow_version"))
        assertEquals(256, json.getInt("ipfix_template_id"))
        assertTrue(json.getJSONArray("ipfix_elements").length() >= 6)
    }
}
