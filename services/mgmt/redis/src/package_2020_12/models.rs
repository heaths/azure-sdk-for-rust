#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sku {
    pub name: sku::Name,
    pub family: sku::Family,
    pub capacity: i32,
}
pub mod sku {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Name {
        Basic,
        Standard,
        Premium,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Family {
        C,
        P,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisCommonProperties {
    #[serde(rename = "redisConfiguration", default, skip_serializing_if = "Option::is_none")]
    pub redis_configuration: Option<serde_json::Value>,
    #[serde(rename = "redisVersion", default, skip_serializing_if = "Option::is_none")]
    pub redis_version: Option<String>,
    #[serde(rename = "enableNonSslPort", default, skip_serializing_if = "Option::is_none")]
    pub enable_non_ssl_port: Option<bool>,
    #[serde(rename = "replicasPerMaster", default, skip_serializing_if = "Option::is_none")]
    pub replicas_per_master: Option<i32>,
    #[serde(rename = "replicasPerPrimary", default, skip_serializing_if = "Option::is_none")]
    pub replicas_per_primary: Option<i32>,
    #[serde(rename = "tenantSettings", default, skip_serializing_if = "Option::is_none")]
    pub tenant_settings: Option<serde_json::Value>,
    #[serde(rename = "shardCount", default, skip_serializing_if = "Option::is_none")]
    pub shard_count: Option<i32>,
    #[serde(rename = "minimumTlsVersion", default, skip_serializing_if = "Option::is_none")]
    pub minimum_tls_version: Option<redis_common_properties::MinimumTlsVersion>,
    #[serde(rename = "publicNetworkAccess", default, skip_serializing_if = "Option::is_none")]
    pub public_network_access: Option<redis_common_properties::PublicNetworkAccess>,
}
pub mod redis_common_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum MinimumTlsVersion {
        #[serde(rename = "1.0")]
        _1_0,
        #[serde(rename = "1.1")]
        _1_1,
        #[serde(rename = "1.2")]
        _1_2,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum PublicNetworkAccess {
        Enabled,
        Disabled,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisCreateProperties {
    #[serde(flatten)]
    pub redis_common_properties: RedisCommonProperties,
    pub sku: Sku,
    #[serde(rename = "subnetId", default, skip_serializing_if = "Option::is_none")]
    pub subnet_id: Option<String>,
    #[serde(rename = "staticIP", default, skip_serializing_if = "Option::is_none")]
    pub static_ip: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisUpdateProperties {
    #[serde(flatten)]
    pub redis_common_properties: RedisCommonProperties,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisProperties {
    #[serde(flatten)]
    pub redis_create_properties: RedisCreateProperties,
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<redis_properties::ProvisioningState>,
    #[serde(rename = "hostName", default, skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    #[serde(rename = "sslPort", default, skip_serializing_if = "Option::is_none")]
    pub ssl_port: Option<i32>,
    #[serde(rename = "accessKeys", default, skip_serializing_if = "Option::is_none")]
    pub access_keys: Option<RedisAccessKeys>,
    #[serde(rename = "linkedServers", default, skip_serializing_if = "Vec::is_empty")]
    pub linked_servers: Vec<RedisLinkedServer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<RedisInstanceDetails>,
    #[serde(rename = "privateEndpointConnections", default, skip_serializing_if = "Vec::is_empty")]
    pub private_endpoint_connections: Vec<PrivateEndpointConnection>,
}
pub mod redis_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ProvisioningState {
        Creating,
        Deleting,
        Disabled,
        Failed,
        Linking,
        Provisioning,
        RecoveringScaleFailure,
        Scaling,
        Succeeded,
        Unlinking,
        Unprovisioning,
        Updating,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisCreateParameters {
    pub properties: RedisCreateProperties,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisUpdateParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<RedisUpdateProperties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisAccessKeys {
    #[serde(rename = "primaryKey", default, skip_serializing_if = "Option::is_none")]
    pub primary_key: Option<String>,
    #[serde(rename = "secondaryKey", default, skip_serializing_if = "Option::is_none")]
    pub secondary_key: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisFirewallRule {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    pub properties: RedisFirewallRuleProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisFirewallRuleCreateParameters {
    #[serde(flatten)]
    pub redis_firewall_rule: RedisFirewallRule,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisFirewallRuleProperties {
    #[serde(rename = "startIP")]
    pub start_ip: String,
    #[serde(rename = "endIP")]
    pub end_ip: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisFirewallRuleListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<RedisFirewallRule>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisResource {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    pub properties: RedisProperties,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisInstanceDetails {
    #[serde(rename = "sslPort", default, skip_serializing_if = "Option::is_none")]
    pub ssl_port: Option<i32>,
    #[serde(rename = "nonSslPort", default, skip_serializing_if = "Option::is_none")]
    pub non_ssl_port: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(rename = "shardId", default, skip_serializing_if = "Option::is_none")]
    pub shard_id: Option<i32>,
    #[serde(rename = "isMaster", default, skip_serializing_if = "Option::is_none")]
    pub is_master: Option<bool>,
    #[serde(rename = "isPrimary", default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<RedisResource>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisRegenerateKeyParameters {
    #[serde(rename = "keyType")]
    pub key_type: redis_regenerate_key_parameters::KeyType,
}
pub mod redis_regenerate_key_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum KeyType {
        Primary,
        Secondary,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisRebootParameters {
    #[serde(rename = "rebootType", default, skip_serializing_if = "Option::is_none")]
    pub reboot_type: Option<redis_reboot_parameters::RebootType>,
    #[serde(rename = "shardId", default, skip_serializing_if = "Option::is_none")]
    pub shard_id: Option<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<i64>,
}
pub mod redis_reboot_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum RebootType {
        PrimaryNode,
        SecondaryNode,
        AllNodes,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportRdbParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub prefix: String,
    pub container: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImportRdbParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub files: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScheduleEntry {
    #[serde(rename = "dayOfWeek")]
    pub day_of_week: schedule_entry::DayOfWeek,
    #[serde(rename = "startHourUtc")]
    pub start_hour_utc: i32,
    #[serde(rename = "maintenanceWindow", default, skip_serializing_if = "Option::is_none")]
    pub maintenance_window: Option<String>,
}
pub mod schedule_entry {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum DayOfWeek {
        Monday,
        Tuesday,
        Wednesday,
        Thursday,
        Friday,
        Saturday,
        Sunday,
        Everyday,
        Weekend,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScheduleEntries {
    #[serde(rename = "scheduleEntries")]
    pub schedule_entries: Vec<ScheduleEntry>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisPatchSchedule {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    pub properties: ScheduleEntries,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisPatchScheduleListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<RedisPatchSchedule>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisForceRebootResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisLinkedServer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisLinkedServerWithProperties {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<RedisLinkedServerProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisLinkedServerProperties {
    #[serde(flatten)]
    pub redis_linked_server_create_properties: RedisLinkedServerCreateProperties,
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisLinkedServerWithPropertiesList {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<RedisLinkedServerWithProperties>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisLinkedServerCreateProperties {
    #[serde(rename = "linkedRedisCacheId")]
    pub linked_redis_cache_id: String,
    #[serde(rename = "linkedRedisCacheLocation")]
    pub linked_redis_cache_location: String,
    #[serde(rename = "serverRole")]
    pub server_role: redis_linked_server_create_properties::ServerRole,
}
pub mod redis_linked_server_create_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ServerRole {
        Primary,
        Secondary,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedisLinkedServerCreateParameters {
    pub properties: RedisLinkedServerCreateProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<operation::Display>,
}
pub mod operation {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Display {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Operation>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckNameAvailabilityParameters {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpgradeNotification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(rename = "upsellNotification", default, skip_serializing_if = "Option::is_none")]
    pub upsell_notification: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationListResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<UpgradeNotification>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<ErrorDetail>,
    #[serde(rename = "additionalInfo", default, skip_serializing_if = "Vec::is_empty")]
    pub additional_info: Vec<ErrorAdditionalInfo>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorAdditionalInfo {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateEndpointConnectionListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<PrivateEndpointConnection>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateEndpointConnection {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<PrivateEndpointConnectionProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateEndpointConnectionProperties {
    #[serde(rename = "privateEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub private_endpoint: Option<PrivateEndpoint>,
    #[serde(rename = "privateLinkServiceConnectionState")]
    pub private_link_service_connection_state: PrivateLinkServiceConnectionState,
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<PrivateEndpointConnectionProvisioningState>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateLinkServiceConnectionState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<PrivateEndpointServiceConnectionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "actionsRequired", default, skip_serializing_if = "Option::is_none")]
    pub actions_required: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PrivateEndpointServiceConnectionStatus {
    Pending,
    Approved,
    Rejected,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PrivateEndpointConnectionProvisioningState {
    Succeeded,
    Creating,
    Deleting,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateLinkResourceListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<PrivateLinkResource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateLinkResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<PrivateLinkResourceProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateLinkResourceProperties {
    #[serde(rename = "groupId", default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(rename = "requiredMembers", default, skip_serializing_if = "Vec::is_empty")]
    pub required_members: Vec<String>,
    #[serde(rename = "requiredZoneNames", default, skip_serializing_if = "Vec::is_empty")]
    pub required_zone_names: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxyResource {
    #[serde(flatten)]
    pub resource: Resource,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackedResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    pub location: String,
}