#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationListResult {
    #[serde(skip_serializing)]
    pub value: Vec<OperationValue>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationValue {
    #[serde(skip_serializing)]
    pub origin: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<OperationValueDisplay>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationValueDisplay {
    #[serde(skip_serializing)]
    pub operation: Option<String>,
    #[serde(skip_serializing)]
    pub resource: Option<String>,
    #[serde(skip_serializing)]
    pub description: Option<String>,
    #[serde(skip_serializing)]
    pub provider: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OsProfile {
    #[serde(rename = "computerName", skip_serializing)]
    pub computer_name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MachineProperties {
    #[serde(rename = "osProfile", skip_serializing)]
    pub os_profile: Option<OsProfile>,
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<String>,
    #[serde(skip_serializing)]
    pub status: Option<machine_properties::Status>,
    #[serde(rename = "lastStatusChange", skip_serializing)]
    pub last_status_change: Option<String>,
    #[serde(rename = "errorDetails", skip_serializing)]
    pub error_details: Vec<ErrorDetail>,
    #[serde(rename = "agentVersion", skip_serializing)]
    pub agent_version: Option<String>,
    #[serde(rename = "vmId", skip_serializing)]
    pub vm_id: Option<String>,
    #[serde(rename = "displayName", skip_serializing)]
    pub display_name: Option<String>,
    #[serde(rename = "machineFqdn", skip_serializing)]
    pub machine_fqdn: Option<String>,
    #[serde(rename = "physicalLocation", default, skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<String>,
    #[serde(rename = "clientPublicKey", default, skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<String>,
    #[serde(rename = "osName", skip_serializing)]
    pub os_name: Option<String>,
    #[serde(rename = "osVersion", skip_serializing)]
    pub os_version: Option<String>,
}
pub mod machine_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Status {
        Connected,
        Disconnected,
        Error,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MachineReconnectProperties {
    #[serde(rename = "vmId", default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    #[serde(rename = "clientPublicKey", default, skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MachineUpdateProperties {
    #[serde(rename = "physicalLocation", default, skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Machine {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<MachineProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MachineUpdate {
    #[serde(flatten)]
    pub update_resource: UpdateResource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<MachineUpdateProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MachineReconnect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<MachineReconnectProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MachineListResult {
    pub value: Vec<Machine>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateResource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<ErrorDetail>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "principalId", skip_serializing)]
    pub principal_id: Option<String>,
    #[serde(rename = "tenantId", skip_serializing)]
    pub tenant_id: Option<String>,
}
