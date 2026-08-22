use serde::{Deserialize, Serialize};

use crate::account::Device;
use crate::rtc::{InboundRtcSignal, RtcSignalEnvelope};
use crate::NodeInfo;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "cmd", content = "data")]
pub enum WsMessage {
    Ping,
    Pong {
        timestamp: u64,
    },

    #[serde(rename = "list_nodes")]
    ListNodes,
    #[serde(rename = "rtc_signal")]
    RtcSignal(RtcSignalEnvelope),
    #[serde(rename = "update_node_info")]
    UpdateNodeInfo(NodeInfo),

    #[serde(rename = "nodes_list")]
    NodesList {
        nodes: Vec<NodeInfo>,
    },
    #[serde(rename = "inbound_rtc_signal")]
    InboundRtcSignal(InboundRtcSignal),
    #[serde(rename = "device_updated")]
    DeviceUpdated {
        device_id: String,
    },
    #[serde(rename = "device_added")]
    DeviceAdded(Device),
    #[serde(rename = "device_deleted")]
    DeviceDeleted {
        device_id: String,
    },
}
