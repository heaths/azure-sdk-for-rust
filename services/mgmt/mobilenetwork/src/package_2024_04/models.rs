#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::de::{value, Deserializer, IntoDeserializer};
use serde::{Deserialize, Serialize, Serializer};
use std::str::FromStr;
pub type N5Qi = i32;
pub type N5QiPriorityLevel = i32;
pub type N5QiPriorityLevelRm = i32;
pub type N5QiRm = i32;
#[doc = "Aggregate maximum bit rate."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ambr {
    #[doc = "Bit rate."]
    pub uplink: BitRate,
    #[doc = "Bit rate."]
    pub downlink: BitRate,
}
impl Ambr {
    pub fn new(uplink: BitRate, downlink: BitRate) -> Self {
        Self { uplink, downlink }
    }
}
#[doc = "Aggregate maximum bit rate."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AmbrRm {
    #[doc = "Bit rate."]
    pub uplink: BitRate,
    #[doc = "Bit rate."]
    pub downlink: BitRate,
}
impl AmbrRm {
    pub fn new(uplink: BitRate, downlink: BitRate) -> Self {
        Self { uplink, downlink }
    }
}
#[doc = "AMF identifier"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AmfId {
    #[doc = "AMF region identifier"]
    #[serde(rename = "regionId")]
    pub region_id: i32,
    #[doc = "AMF set identifier"]
    #[serde(rename = "setId")]
    pub set_id: i32,
    #[doc = "AMF pointer"]
    pub pointer: i32,
}
impl AmfId {
    pub fn new(region_id: i32, set_id: i32, pointer: i32) -> Self {
        Self {
            region_id,
            set_id,
            pointer,
        }
    }
}
#[doc = "Allocation and Retention Priority (ARP) parameters."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Arp {
    #[doc = "ARP priority level."]
    #[serde(rename = "priorityLevel")]
    pub priority_level: ArpPriorityLevel,
    #[doc = "Preemption capability."]
    #[serde(rename = "preemptCap")]
    pub preempt_cap: PreemptionCapability,
    #[doc = "Preemption vulnerability."]
    #[serde(rename = "preemptVuln")]
    pub preempt_vuln: PreemptionVulnerability,
}
impl Arp {
    pub fn new(priority_level: ArpPriorityLevel, preempt_cap: PreemptionCapability, preempt_vuln: PreemptionVulnerability) -> Self {
        Self {
            priority_level,
            preempt_cap,
            preempt_vuln,
        }
    }
}
pub type ArpPriorityLevel = i32;
pub type ArpPriorityLevelRm = i32;
#[doc = "Reference to an Azure Async Operation ID."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AsyncOperationId {
    #[doc = "Azure Async Operation ID."]
    pub id: String,
}
impl AsyncOperationId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "The current status of an async operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AsyncOperationStatus {
    #[doc = "Fully qualified ID for the async operation."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[doc = "Name of the async operation."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "The operation status."]
    pub status: String,
    #[doc = "Fully qualified ID for the resource that this async operation status relates to."]
    #[serde(rename = "resourceId", default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[doc = "The start time of the operation."]
    #[serde(rename = "startTime", default, with = "azure_core::date::rfc3339::option")]
    pub start_time: Option<::time::OffsetDateTime>,
    #[doc = "The end time of the operation."]
    #[serde(rename = "endTime", default, with = "azure_core::date::rfc3339::option")]
    pub end_time: Option<::time::OffsetDateTime>,
    #[doc = "Percentage of the operation that is complete."]
    #[serde(rename = "percentComplete", default, skip_serializing_if = "Option::is_none")]
    pub percent_complete: Option<f64>,
    #[doc = "Properties returned by the resource provider on a successful operation"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
    #[doc = "The error detail."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}
impl AsyncOperationStatus {
    pub fn new(status: String) -> Self {
        Self {
            id: None,
            name: None,
            status,
            resource_id: None,
            start_time: None,
            end_time: None,
            percent_complete: None,
            properties: None,
            error: None,
        }
    }
}
#[doc = "Attached data network resource. Must be created in the same location as its parent packet core data plane."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttachedDataNetwork {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Data network properties."]
    pub properties: AttachedDataNetworkPropertiesFormat,
}
impl AttachedDataNetwork {
    pub fn new(tracked_resource: TrackedResource, properties: AttachedDataNetworkPropertiesFormat) -> Self {
        Self {
            tracked_resource,
            properties,
        }
    }
}
#[doc = "Response for attached data network API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AttachedDataNetworkListResult {
    #[doc = "A list of data networks in a resource group."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<AttachedDataNetwork>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for AttachedDataNetworkListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl AttachedDataNetworkListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Data network properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttachedDataNetworkPropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "Interface properties"]
    #[serde(rename = "userPlaneDataInterface")]
    pub user_plane_data_interface: InterfaceProperties,
    #[doc = "The DNS servers to signal to UEs to use for this attached data network. This configuration is mandatory - if you don't want DNS servers, you must provide an empty array."]
    #[serde(rename = "dnsAddresses")]
    pub dns_addresses: Vec<Ipv4Addr>,
    #[doc = "The network address and port translation settings to use for the attached data network."]
    #[serde(rename = "naptConfiguration", default, skip_serializing_if = "Option::is_none")]
    pub napt_configuration: Option<NaptConfiguration>,
    #[doc = "The user equipment (UE) address pool prefixes for the attached data network from which the packet core instance will dynamically assign IP addresses to UEs.\nThe packet core instance assigns an IP address to a UE when the UE sets up a PDU session.\n You must define at least one of userEquipmentAddressPoolPrefix and userEquipmentStaticAddressPoolPrefix. If you define both, they must be of the same size."]
    #[serde(
        rename = "userEquipmentAddressPoolPrefix",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub user_equipment_address_pool_prefix: Vec<Ipv4AddrMask>,
    #[doc = "The user equipment (UE) address pool prefixes for the attached data network from which the packet core instance will assign static IP addresses to UEs.\nThe packet core instance assigns an IP address to a UE when the UE sets up a PDU session. The static IP address for a specific UE is set in StaticIPConfiguration on the corresponding SIM resource.\nAt least one of userEquipmentAddressPoolPrefix and userEquipmentStaticAddressPoolPrefix must be defined. If both are defined, they must be of the same size."]
    #[serde(
        rename = "userEquipmentStaticAddressPoolPrefix",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub user_equipment_static_address_pool_prefix: Vec<Ipv4AddrMask>,
}
impl AttachedDataNetworkPropertiesFormat {
    pub fn new(user_plane_data_interface: InterfaceProperties, dns_addresses: Vec<Ipv4Addr>) -> Self {
        Self {
            provisioning_state: None,
            user_plane_data_interface,
            dns_addresses,
            napt_configuration: None,
            user_equipment_address_pool_prefix: Vec::new(),
            user_equipment_static_address_pool_prefix: Vec::new(),
        }
    }
}
#[doc = "Reference to an attached data network resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttachedDataNetworkResourceId {
    #[doc = "Attached data network resource ID."]
    pub id: String,
}
impl AttachedDataNetworkResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "Reference to an Azure Stack Edge device resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AzureStackEdgeDeviceResourceId {
    #[doc = "Azure Stack Edge device resource ID."]
    pub id: String,
}
impl AzureStackEdgeDeviceResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "Reference to an Azure Stack HCI cluster resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AzureStackHciClusterResourceId {
    #[doc = "Azure Stack HCI cluster resource ID."]
    pub id: String,
}
impl AzureStackHciClusterResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "The SKU of the packet core control plane resource. The SKU list may change over time when a new SKU gets added or an exiting SKU gets removed."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "BillingSku")]
pub enum BillingSku {
    G0,
    G1,
    G2,
    G5,
    G10,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for BillingSku {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for BillingSku {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for BillingSku {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::G0 => serializer.serialize_unit_variant("BillingSku", 0u32, "G0"),
            Self::G1 => serializer.serialize_unit_variant("BillingSku", 1u32, "G1"),
            Self::G2 => serializer.serialize_unit_variant("BillingSku", 2u32, "G2"),
            Self::G5 => serializer.serialize_unit_variant("BillingSku", 3u32, "G5"),
            Self::G10 => serializer.serialize_unit_variant("BillingSku", 4u32, "G10"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
pub type BitRate = String;
pub type BitRateRm = String;
#[doc = "Certificate provisioning state"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CertificateProvisioning {
    #[doc = "The certificate's provisioning state"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<certificate_provisioning::State>,
    #[doc = "Reason for certificate provisioning failure."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
impl CertificateProvisioning {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod certificate_provisioning {
    use super::*;
    #[doc = "The certificate's provisioning state"]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "State")]
    pub enum State {
        NotProvisioned,
        Provisioned,
        Failed,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for State {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for State {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for State {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::NotProvisioned => serializer.serialize_unit_variant("State", 0u32, "NotProvisioned"),
                Self::Provisioned => serializer.serialize_unit_variant("State", 1u32, "Provisioned"),
                Self::Failed => serializer.serialize_unit_variant("State", 2u32, "Failed"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
}
#[doc = "Common SIM properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommonSimPropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "The state of the SIM resource."]
    #[serde(rename = "simState", default, skip_serializing_if = "Option::is_none")]
    pub sim_state: Option<SimState>,
    #[doc = "The provisioning state of a resource e.g. SIM/SIM policy on a site. The dictionary keys will ARM resource IDs in the form: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MobileNetwork/mobileNetworks/{mobileNetworkName}/sites/{siteName}. The dictionary values will be from the \"SiteProvisioningState\" enum."]
    #[serde(rename = "siteProvisioningState", default, skip_serializing_if = "Option::is_none")]
    pub site_provisioning_state: Option<SiteProvisioning>,
    #[doc = "The international mobile subscriber identity (IMSI) for the SIM."]
    #[serde(rename = "internationalMobileSubscriberIdentity")]
    pub international_mobile_subscriber_identity: String,
    #[doc = "The integrated circuit card ID (ICCID) for the SIM."]
    #[serde(rename = "integratedCircuitCardIdentifier", default, skip_serializing_if = "Option::is_none")]
    pub integrated_circuit_card_identifier: Option<String>,
    #[doc = "An optional free-form text field that can be used to record the device type this SIM is associated with, for example 'Video camera'. The Azure portal allows SIMs to be grouped and filtered based on this value."]
    #[serde(rename = "deviceType", default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[doc = "Reference to a SIM policy resource."]
    #[serde(rename = "simPolicy", default, skip_serializing_if = "Option::is_none")]
    pub sim_policy: Option<SimPolicyResourceId>,
    #[doc = "A list of static IP addresses assigned to this SIM. Each address is assigned at a defined network scope, made up of {attached data network, slice}."]
    #[serde(
        rename = "staticIpConfiguration",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub static_ip_configuration: Vec<SimStaticIpProperties>,
    #[doc = "The name of the SIM vendor who provided this SIM, if any."]
    #[serde(rename = "vendorName", default, skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    #[doc = "The public key fingerprint of the SIM vendor who provided this SIM, if any."]
    #[serde(rename = "vendorKeyFingerprint", default, skip_serializing_if = "Option::is_none")]
    pub vendor_key_fingerprint: Option<String>,
}
impl CommonSimPropertiesFormat {
    pub fn new(international_mobile_subscriber_identity: String) -> Self {
        Self {
            provisioning_state: None,
            sim_state: None,
            site_provisioning_state: None,
            international_mobile_subscriber_identity,
            integrated_circuit_card_identifier: None,
            device_type: None,
            sim_policy: None,
            static_ip_configuration: Vec::new(),
            vendor_name: None,
            vendor_key_fingerprint: None,
        }
    }
}
#[doc = "Reference to an Azure Arc custom location resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectedClusterResourceId {
    #[doc = "Azure Arc connected cluster resource ID."]
    pub id: String,
}
impl ConnectedClusterResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "The core network technology generation (5G core, EPC / 4G core or EPC / 4G + 5G core)."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CoreNetworkType {
    #[serde(rename = "5GC")]
    N5GC,
    #[serde(rename = "EPC")]
    Epc,
    #[serde(rename = "EPC + 5GC")]
    Epc5gc,
}
impl Default for CoreNetworkType {
    fn default() -> Self {
        Self::N5GC
    }
}
#[doc = "The core network technology generation (5G core, EPC / 4G core or EPC / 4G + 5G core)."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CoreNetworkTypeRm {
    #[serde(rename = "5GC")]
    N5GC,
    #[serde(rename = "EPC")]
    Epc,
    #[serde(rename = "EPC + 5GC")]
    Epc5gc,
}
impl Default for CoreNetworkTypeRm {
    fn default() -> Self {
        Self::N5GC
    }
}
#[doc = "Reference to an Azure Arc custom location resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomLocationResourceId {
    #[doc = "Azure Arc custom location resource ID."]
    pub id: String,
}
impl CustomLocationResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "Data network resource. Must be created in the same location as its parent mobile network."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataNetwork {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Data network properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<DataNetworkPropertiesFormat>,
}
impl DataNetwork {
    pub fn new(tracked_resource: TrackedResource) -> Self {
        Self {
            tracked_resource,
            properties: None,
        }
    }
}
#[doc = "Settings controlling data network use"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataNetworkConfiguration {
    #[doc = "Reference to a data network resource."]
    #[serde(rename = "dataNetwork")]
    pub data_network: DataNetworkResourceId,
    #[doc = "Aggregate maximum bit rate."]
    #[serde(rename = "sessionAmbr")]
    pub session_ambr: Ambr,
    #[doc = "5G QoS Identifier."]
    #[serde(rename = "5qi", default, skip_serializing_if = "Option::is_none")]
    pub n5qi: Option<N5Qi>,
    #[doc = "ARP priority level."]
    #[serde(rename = "allocationAndRetentionPriorityLevel", default, skip_serializing_if = "Option::is_none")]
    pub allocation_and_retention_priority_level: Option<ArpPriorityLevel>,
    #[doc = "Preemption capability."]
    #[serde(rename = "preemptionCapability", default, skip_serializing_if = "Option::is_none")]
    pub preemption_capability: Option<PreemptionCapability>,
    #[doc = "Preemption vulnerability."]
    #[serde(rename = "preemptionVulnerability", default, skip_serializing_if = "Option::is_none")]
    pub preemption_vulnerability: Option<PreemptionVulnerability>,
    #[doc = "PDU session type (IPv4/IPv6)."]
    #[serde(rename = "defaultSessionType", default, skip_serializing_if = "Option::is_none")]
    pub default_session_type: Option<PduSessionType>,
    #[doc = "Allowed session types in addition to the default session type. Must not duplicate the default session type."]
    #[serde(
        rename = "additionalAllowedSessionTypes",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub additional_allowed_session_types: Vec<PduSessionType>,
    #[doc = "List of services that can be used as part of this SIM policy. The list must not contain duplicate items and must contain at least one item. The services must be in the same location as the SIM policy."]
    #[serde(rename = "allowedServices")]
    pub allowed_services: Vec<ServiceResourceId>,
    #[doc = "The maximum number of downlink packets to buffer at the user plane for High Latency Communication - Extended Buffering. See 3GPP TS29.272 v15.10.0 section 7.3.188 for a full description. This maximum is not guaranteed because there is a internal limit on buffered packets across all PDU sessions."]
    #[serde(rename = "maximumNumberOfBufferedPackets", default, skip_serializing_if = "Option::is_none")]
    pub maximum_number_of_buffered_packets: Option<i32>,
}
impl DataNetworkConfiguration {
    pub fn new(data_network: DataNetworkResourceId, session_ambr: Ambr, allowed_services: Vec<ServiceResourceId>) -> Self {
        Self {
            data_network,
            session_ambr,
            n5qi: None,
            allocation_and_retention_priority_level: None,
            preemption_capability: None,
            preemption_vulnerability: None,
            default_session_type: None,
            additional_allowed_session_types: Vec::new(),
            allowed_services,
            maximum_number_of_buffered_packets: None,
        }
    }
}
#[doc = "Response for data network API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DataNetworkListResult {
    #[doc = "A list of data networks."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<DataNetwork>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for DataNetworkListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl DataNetworkListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Data network properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DataNetworkPropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "An optional description for this data network."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
impl DataNetworkPropertiesFormat {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Reference to a data network resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataNetworkResourceId {
    #[doc = "Data network resource ID."]
    pub id: String,
}
impl DataNetworkResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "The desired installation state of the packet core."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "DesiredInstallationState")]
pub enum DesiredInstallationState {
    Uninstalled,
    Installed,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for DesiredInstallationState {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for DesiredInstallationState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for DesiredInstallationState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Uninstalled => serializer.serialize_unit_variant("DesiredInstallationState", 0u32, "Uninstalled"),
            Self::Installed => serializer.serialize_unit_variant("DesiredInstallationState", 1u32, "Installed"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Diagnostics package resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsPackage {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Diagnostics package properties."]
    pub properties: DiagnosticsPackagePropertiesFormat,
}
impl DiagnosticsPackage {
    pub fn new(properties: DiagnosticsPackagePropertiesFormat) -> Self {
        Self {
            proxy_resource: ProxyResource::default(),
            properties,
        }
    }
}
#[doc = "Response for diagnostics package API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DiagnosticsPackageListResult {
    #[doc = "A list of diagnostics packages under a packet core control plane."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<DiagnosticsPackage>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for DiagnosticsPackageListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl DiagnosticsPackageListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Diagnostics package properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DiagnosticsPackagePropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "The status of the diagnostics package collection."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<diagnostics_package_properties_format::Status>,
    #[doc = "The reason for the current state of the diagnostics package collection."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
impl DiagnosticsPackagePropertiesFormat {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod diagnostics_package_properties_format {
    use super::*;
    #[doc = "The status of the diagnostics package collection."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "Status")]
    pub enum Status {
        NotStarted,
        Collecting,
        Collected,
        Error,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for Status {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for Status {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for Status {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::NotStarted => serializer.serialize_unit_variant("Status", 0u32, "NotStarted"),
                Self::Collecting => serializer.serialize_unit_variant("Status", 1u32, "Collecting"),
                Self::Collected => serializer.serialize_unit_variant("Status", 2u32, "Collected"),
                Self::Error => serializer.serialize_unit_variant("Status", 3u32, "Error"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
}
#[doc = "Configuration for uploading packet core diagnostics."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsUploadConfiguration {
    #[doc = "The Storage Account Container URL to upload diagnostics to."]
    #[serde(rename = "storageAccountContainerUrl")]
    pub storage_account_container_url: String,
}
impl DiagnosticsUploadConfiguration {
    pub fn new(storage_account_container_url: String) -> Self {
        Self {
            storage_account_container_url,
        }
    }
}
pub type Dnn = String;
#[doc = "DNN and UE IP address"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct DnnIpPair {
    #[doc = "Data network name"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnn: Option<Dnn>,
    #[doc = "UE IP address"]
    #[serde(rename = "ueIpAddress", default, skip_serializing_if = "Option::is_none")]
    pub ue_ip_address: Option<UeIpAddress>,
}
impl DnnIpPair {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Encrypted SIM properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedSimPropertiesFormat {
    #[serde(flatten)]
    pub common_sim_properties_format: CommonSimPropertiesFormat,
    #[doc = "The encrypted SIM credentials."]
    #[serde(rename = "encryptedCredentials", default, skip_serializing_if = "Option::is_none")]
    pub encrypted_credentials: Option<String>,
}
impl EncryptedSimPropertiesFormat {
    pub fn new(common_sim_properties_format: CommonSimPropertiesFormat) -> Self {
        Self {
            common_sim_properties_format,
            encrypted_credentials: None,
        }
    }
}
#[doc = "The SIMs to upload. The SIM credentials must be encrypted."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedSimUploadList {
    #[doc = "The upload file format version."]
    pub version: i32,
    #[doc = "An identifier for the Azure SIM onboarding public key used for encrypted upload."]
    #[serde(rename = "azureKeyIdentifier")]
    pub azure_key_identifier: i32,
    #[doc = "The fingerprint of the SIM vendor public key. The private counterpart is used for signing the encrypted transport key."]
    #[serde(rename = "vendorKeyFingerprint")]
    pub vendor_key_fingerprint: String,
    #[doc = "The transport key used for encrypting SIM credentials, encrypted using the SIM onboarding public key."]
    #[serde(rename = "encryptedTransportKey")]
    pub encrypted_transport_key: String,
    #[doc = "The encrypted transport key, signed using the SIM vendor private key."]
    #[serde(rename = "signedTransportKey")]
    pub signed_transport_key: String,
    #[doc = "A list of SIMs to upload, with encrypted properties."]
    pub sims: Vec<SimNameAndEncryptedProperties>,
}
impl EncryptedSimUploadList {
    pub fn new(
        version: i32,
        azure_key_identifier: i32,
        vendor_key_fingerprint: String,
        encrypted_transport_key: String,
        signed_transport_key: String,
        sims: Vec<SimNameAndEncryptedProperties>,
    ) -> Self {
        Self {
            version,
            azure_key_identifier,
            vendor_key_fingerprint,
            encrypted_transport_key,
            signed_transport_key,
            sims,
        }
    }
}
#[doc = "The resource management error additional info."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ErrorAdditionalInfo {
    #[doc = "The additional info type."]
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[doc = "The additional info."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<serde_json::Value>,
}
impl ErrorAdditionalInfo {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The error detail."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ErrorDetail {
    #[doc = "The error code."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[doc = "The error message."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[doc = "The error target."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[doc = "The error details."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub details: Vec<ErrorDetail>,
    #[doc = "The error additional info."]
    #[serde(
        rename = "additionalInfo",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub additional_info: Vec<ErrorAdditionalInfo>,
}
impl ErrorDetail {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Common error response for all Azure Resource Manager APIs to return error details for failed operations. (This also follows the OData error response format.)."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ErrorResponse {
    #[doc = "The error detail."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}
impl azure_core::Continuable for ErrorResponse {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        None
    }
}
impl ErrorResponse {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Configuration for sending packet core events to Azure Event Hub."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventHubConfiguration {
    #[doc = "Resource ID  of Azure Event Hub to send packet core events to."]
    pub id: String,
    #[doc = "The duration (in seconds) between UE usage reports."]
    #[serde(rename = "reportingInterval", default, skip_serializing_if = "Option::is_none")]
    pub reporting_interval: Option<i32>,
}
impl EventHubConfiguration {
    pub fn new(id: String) -> Self {
        Self {
            id,
            reporting_interval: None,
        }
    }
}
#[doc = "Extended User Equipment (UE) information."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtendedUeInfo {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Extended UE Information Properties."]
    pub properties: ExtendedUeInfoPropertiesUnion,
}
impl ExtendedUeInfo {
    pub fn new(properties: ExtendedUeInfoPropertiesUnion) -> Self {
        Self {
            proxy_resource: ProxyResource::default(),
            properties,
        }
    }
}
#[doc = "Extended UE Information Properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtendedUeInfoProperties {
    #[doc = "The timestamp of last UE info read from the packet core (UTC)."]
    #[serde(rename = "lastReadAt", default, with = "azure_core::date::rfc3339::option")]
    pub last_read_at: Option<::time::OffsetDateTime>,
}
impl ExtendedUeInfoProperties {
    pub fn new() -> Self {
        Self { last_read_at: None }
    }
}
#[doc = "RAT Type"]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "ratType")]
pub enum ExtendedUeInfoPropertiesUnion {
    #[serde(rename = "4G")]
    N4G(UeInfo4G),
    #[serde(rename = "5G")]
    N5G(UeInfo5G),
}
#[doc = "gNodeB identifier"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct GNbId {
    #[serde(rename = "bitLength", default, skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<i32>,
    #[serde(rename = "gNBValue", default, skip_serializing_if = "Option::is_none")]
    pub g_nb_value: Option<String>,
}
impl GNbId {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Global RAN Node ID"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GlobalRanNodeId {
    #[doc = "Public land mobile network (PLMN) ID. This is made up of the mobile country code and mobile network code, as defined in https://www.itu.int/rec/T-REC-E.212. The values 001-01 and 001-001 can be used for testing and the values 999-99 and 999-999 can be used on internal private networks."]
    #[serde(rename = "plmnId")]
    pub plmn_id: PlmnId,
    #[doc = "gNodeB identifier"]
    #[serde(rename = "gNbId", default, skip_serializing_if = "Option::is_none")]
    pub g_nb_id: Option<GNbId>,
    #[doc = "NG-eNodeB identifier"]
    #[serde(rename = "ngeNbId", default, skip_serializing_if = "Option::is_none")]
    pub nge_nb_id: Option<String>,
    #[doc = "eNodeB identifier"]
    #[serde(rename = "eNbId", default, skip_serializing_if = "Option::is_none")]
    pub e_nb_id: Option<String>,
    #[doc = "N3 IWF identifier"]
    #[serde(rename = "n3IwfId", default, skip_serializing_if = "Option::is_none")]
    pub n3_iwf_id: Option<String>,
    #[doc = "W-AGF identifier"]
    #[serde(rename = "wagfId", default, skip_serializing_if = "Option::is_none")]
    pub wagf_id: Option<String>,
    #[doc = "TNGF identifier"]
    #[serde(rename = "tngfId", default, skip_serializing_if = "Option::is_none")]
    pub tngf_id: Option<String>,
    #[doc = "Network identifier"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nid: Option<String>,
}
impl GlobalRanNodeId {
    pub fn new(plmn_id: PlmnId) -> Self {
        Self {
            plmn_id,
            g_nb_id: None,
            nge_nb_id: None,
            e_nb_id: None,
            n3_iwf_id: None,
            wagf_id: None,
            tngf_id: None,
            nid: None,
        }
    }
}
#[doc = "Globally Unique Temporary Identifier (4G)"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Guti4G {
    #[doc = "Public land mobile network (PLMN) ID. This is made up of the mobile country code and mobile network code, as defined in https://www.itu.int/rec/T-REC-E.212. The values 001-01 and 001-001 can be used for testing and the values 999-99 and 999-999 can be used on internal private networks."]
    pub plmn: PlmnId,
    #[doc = "MME identifier"]
    #[serde(rename = "mmeId")]
    pub mme_id: MmeId,
    #[doc = "MME Temporary Mobile Subscriber Identity"]
    #[serde(rename = "mTmsi")]
    pub m_tmsi: i64,
}
impl Guti4G {
    pub fn new(plmn: PlmnId, mme_id: MmeId, m_tmsi: i64) -> Self {
        Self { plmn, mme_id, m_tmsi }
    }
}
#[doc = "5G GUTI"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Guti5G {
    #[doc = "Public land mobile network (PLMN) ID. This is made up of the mobile country code and mobile network code, as defined in https://www.itu.int/rec/T-REC-E.212. The values 001-01 and 001-001 can be used for testing and the values 999-99 and 999-999 can be used on internal private networks."]
    pub plmn: PlmnId,
    #[doc = "AMF identifier"]
    #[serde(rename = "amfId")]
    pub amf_id: AmfId,
    #[doc = "5G Temporary Mobile Subscriber Identity"]
    #[serde(rename = "fivegTmsi")]
    pub fiveg_tmsi: i64,
}
impl Guti5G {
    pub fn new(plmn: PlmnId, amf_id: AmfId, fiveg_tmsi: i64) -> Self {
        Self { plmn, amf_id, fiveg_tmsi }
    }
}
#[doc = "HTTPS server certificate configuration."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HttpsServerCertificate {
    #[doc = "The certificate URL, unversioned. For example: https://contosovault.vault.azure.net/certificates/ingress."]
    #[serde(rename = "certificateUrl")]
    pub certificate_url: String,
    #[doc = "Certificate provisioning state"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<CertificateProvisioning>,
}
impl HttpsServerCertificate {
    pub fn new(certificate_url: String) -> Self {
        Self {
            certificate_url,
            provisioning: None,
        }
    }
}
#[doc = "Identity and Tags object for patch operations."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct IdentityAndTagsObject {
    #[doc = "Managed service identity (User assigned identity)"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ManagedServiceIdentity>,
    #[doc = "Resource tags."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl IdentityAndTagsObject {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The installation state of the packet core."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Installation {
    #[doc = "The desired installation state of the packet core."]
    #[serde(rename = "desiredState", default, skip_serializing_if = "Option::is_none")]
    pub desired_state: Option<DesiredInstallationState>,
    #[doc = "The installation state of the packet core."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<InstallationState>,
    #[doc = "Whether a reinstall of the packet core is required to pick up the latest configuration changes."]
    #[serde(rename = "reinstallRequired", default, skip_serializing_if = "Option::is_none")]
    pub reinstall_required: Option<ReinstallRequired>,
    #[doc = "Reason(s) for the current installation state of the packet core."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub reasons: Vec<InstallationReason>,
    #[doc = "Reference to an Azure Async Operation ID."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<AsyncOperationId>,
}
impl Installation {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The reason or list of reasons why a packet core has not been installed or requires a reinstall."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "InstallationReason")]
pub enum InstallationReason {
    NoSlices,
    NoPacketCoreDataPlane,
    NoAttachedDataNetworks,
    PublicLandMobileNetworkIdentifierHasChanged,
    ControlPlaneAccessInterfaceHasChanged,
    UserPlaneAccessInterfaceHasChanged,
    UserPlaneDataInterfaceHasChanged,
    ControlPlaneAccessVirtualIpv4AddressesHasChanged,
    UserPlaneAccessVirtualIpv4AddressesHasChanged,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for InstallationReason {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for InstallationReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for InstallationReason {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::NoSlices => serializer.serialize_unit_variant("InstallationReason", 0u32, "NoSlices"),
            Self::NoPacketCoreDataPlane => serializer.serialize_unit_variant("InstallationReason", 1u32, "NoPacketCoreDataPlane"),
            Self::NoAttachedDataNetworks => serializer.serialize_unit_variant("InstallationReason", 2u32, "NoAttachedDataNetworks"),
            Self::PublicLandMobileNetworkIdentifierHasChanged => {
                serializer.serialize_unit_variant("InstallationReason", 3u32, "PublicLandMobileNetworkIdentifierHasChanged")
            }
            Self::ControlPlaneAccessInterfaceHasChanged => {
                serializer.serialize_unit_variant("InstallationReason", 4u32, "ControlPlaneAccessInterfaceHasChanged")
            }
            Self::UserPlaneAccessInterfaceHasChanged => {
                serializer.serialize_unit_variant("InstallationReason", 5u32, "UserPlaneAccessInterfaceHasChanged")
            }
            Self::UserPlaneDataInterfaceHasChanged => {
                serializer.serialize_unit_variant("InstallationReason", 6u32, "UserPlaneDataInterfaceHasChanged")
            }
            Self::ControlPlaneAccessVirtualIpv4AddressesHasChanged => {
                serializer.serialize_unit_variant("InstallationReason", 7u32, "ControlPlaneAccessVirtualIpv4AddressesHasChanged")
            }
            Self::UserPlaneAccessVirtualIpv4AddressesHasChanged => {
                serializer.serialize_unit_variant("InstallationReason", 8u32, "UserPlaneAccessVirtualIpv4AddressesHasChanged")
            }
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "The installation state of the packet core."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "InstallationState")]
pub enum InstallationState {
    Uninstalled,
    Installing,
    Installed,
    Updating,
    Upgrading,
    Uninstalling,
    Reinstalling,
    RollingBack,
    Failed,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for InstallationState {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for InstallationState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for InstallationState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Uninstalled => serializer.serialize_unit_variant("InstallationState", 0u32, "Uninstalled"),
            Self::Installing => serializer.serialize_unit_variant("InstallationState", 1u32, "Installing"),
            Self::Installed => serializer.serialize_unit_variant("InstallationState", 2u32, "Installed"),
            Self::Updating => serializer.serialize_unit_variant("InstallationState", 3u32, "Updating"),
            Self::Upgrading => serializer.serialize_unit_variant("InstallationState", 4u32, "Upgrading"),
            Self::Uninstalling => serializer.serialize_unit_variant("InstallationState", 5u32, "Uninstalling"),
            Self::Reinstalling => serializer.serialize_unit_variant("InstallationState", 6u32, "Reinstalling"),
            Self::RollingBack => serializer.serialize_unit_variant("InstallationState", 7u32, "RollingBack"),
            Self::Failed => serializer.serialize_unit_variant("InstallationState", 8u32, "Failed"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Interface properties"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InterfaceProperties {
    #[doc = "The logical name for this interface. This should match one of the interfaces configured on your Azure Stack Edge device."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "IPv4 address."]
    #[serde(rename = "ipv4Address", default, skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<Ipv4Addr>,
    #[doc = "IPv4 address prefix."]
    #[serde(rename = "ipv4Subnet", default, skip_serializing_if = "Option::is_none")]
    pub ipv4_subnet: Option<Ipv4AddrMask>,
    #[doc = "IPv4 address."]
    #[serde(rename = "ipv4Gateway", default, skip_serializing_if = "Option::is_none")]
    pub ipv4_gateway: Option<Ipv4Addr>,
    #[doc = "VLAN identifier of the network interface. Example: 501."]
    #[serde(rename = "vlanId", default, skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<i32>,
    #[doc = "The list of IPv4 addresses, for a multi-node system."]
    #[serde(
        rename = "ipv4AddressList",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ipv4_address_list: Vec<Ipv4Addr>,
    #[doc = "The IPv4 addresses of the endpoints to send BFD probes to."]
    #[serde(
        rename = "bfdIpv4Endpoints",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub bfd_ipv4_endpoints: Vec<Ipv4Addr>,
}
impl InterfaceProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
pub type Ipv4Addr = String;
pub type Ipv4AddrMask = String;
pub type Ipv4AddrMaskRm = String;
pub type Ipv4AddrRm = String;
#[doc = "An IPv4 route."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Ipv4Route {
    #[doc = "IPv4 address prefix."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<Ipv4AddrMask>,
    #[doc = "A list of next hops for the destination."]
    #[serde(
        rename = "nextHops",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub next_hops: Vec<Ipv4RouteNextHop>,
}
impl Ipv4Route {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The next hop in an IPv4 route."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Ipv4RouteNextHop {
    #[doc = "IPv4 address."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Ipv4Addr>,
    #[doc = "The priority of this next hop. Next hops with lower preference values are preferred."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}
impl Ipv4RouteNextHop {
    pub fn new() -> Self {
        Self::default()
    }
}
pub type Ipv4Routes = Vec<Ipv4Route>;
#[doc = "An Azure key vault key."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct KeyVaultKey {
    #[doc = "The key URL, unversioned. For example: https://contosovault.vault.azure.net/keys/azureKey."]
    #[serde(rename = "keyUrl", default, skip_serializing_if = "Option::is_none")]
    pub key_url: Option<String>,
}
impl KeyVaultKey {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The kubernetes ingress configuration to control access to packet core diagnostics over local APIs."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalDiagnosticsAccessConfiguration {
    #[doc = "How to authenticate users who access local diagnostics APIs."]
    #[serde(rename = "authenticationType")]
    pub authentication_type: local_diagnostics_access_configuration::AuthenticationType,
    #[doc = "HTTPS server certificate configuration."]
    #[serde(rename = "httpsServerCertificate", default, skip_serializing_if = "Option::is_none")]
    pub https_server_certificate: Option<HttpsServerCertificate>,
}
impl LocalDiagnosticsAccessConfiguration {
    pub fn new(authentication_type: local_diagnostics_access_configuration::AuthenticationType) -> Self {
        Self {
            authentication_type,
            https_server_certificate: None,
        }
    }
}
pub mod local_diagnostics_access_configuration {
    use super::*;
    #[doc = "How to authenticate users who access local diagnostics APIs."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "AuthenticationType")]
    pub enum AuthenticationType {
        #[serde(rename = "AAD")]
        Aad,
        Password,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for AuthenticationType {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for AuthenticationType {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for AuthenticationType {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::Aad => serializer.serialize_unit_variant("AuthenticationType", 0u32, "AAD"),
                Self::Password => serializer.serialize_unit_variant("AuthenticationType", 1u32, "Password"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
}
#[doc = "Managed service identity (User assigned identity)"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedServiceIdentity {
    #[doc = "Type of managed service identity (currently only UserAssigned allowed)."]
    #[serde(rename = "type")]
    pub type_: ManagedServiceIdentityType,
    #[doc = "The set of user assigned identities associated with the resource. The userAssignedIdentities dictionary keys will be ARM resource ids in the form: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName}. The dictionary values can be empty objects ({}) in requests."]
    #[serde(rename = "userAssignedIdentities", default, skip_serializing_if = "Option::is_none")]
    pub user_assigned_identities: Option<UserAssignedIdentities>,
}
impl ManagedServiceIdentity {
    pub fn new(type_: ManagedServiceIdentityType) -> Self {
        Self {
            type_,
            user_assigned_identities: None,
        }
    }
}
#[doc = "Type of managed service identity (currently only UserAssigned allowed)."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ManagedServiceIdentityType")]
pub enum ManagedServiceIdentityType {
    None,
    UserAssigned,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for ManagedServiceIdentityType {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for ManagedServiceIdentityType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for ManagedServiceIdentityType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::None => serializer.serialize_unit_variant("ManagedServiceIdentityType", 0u32, "None"),
            Self::UserAssigned => serializer.serialize_unit_variant("ManagedServiceIdentityType", 1u32, "UserAssigned"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
pub type Mcc = String;
pub type MccRm = String;
#[doc = "MME identifier"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MmeId {
    #[doc = "MME group identifier"]
    #[serde(rename = "groupId")]
    pub group_id: i32,
    #[doc = "MME code"]
    pub code: i32,
}
impl MmeId {
    pub fn new(group_id: i32, code: i32) -> Self {
        Self { group_id, code }
    }
}
pub type Mnc = String;
pub type MncRm = String;
#[doc = "Mobile network resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MobileNetwork {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Mobile network properties."]
    pub properties: MobileNetworkPropertiesFormat,
    #[doc = "Managed service identity (User assigned identity)"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ManagedServiceIdentity>,
}
impl MobileNetwork {
    pub fn new(tracked_resource: TrackedResource, properties: MobileNetworkPropertiesFormat) -> Self {
        Self {
            tracked_resource,
            properties,
            identity: None,
        }
    }
}
#[doc = "Response for mobile networks API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct MobileNetworkListResult {
    #[doc = "A list of mobile networks in a resource group."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<MobileNetwork>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for MobileNetworkListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl MobileNetworkListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Mobile network properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MobileNetworkPropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "Public land mobile network (PLMN) ID. This is made up of the mobile country code and mobile network code, as defined in https://www.itu.int/rec/T-REC-E.212. The values 001-01 and 001-001 can be used for testing and the values 999-99 and 999-999 can be used on internal private networks."]
    #[serde(rename = "publicLandMobileNetworkIdentifier")]
    pub public_land_mobile_network_identifier: PlmnId,
    #[doc = "A list of public land mobile networks including their identifiers. If both 'publicLandMobileNetworks' and 'publicLandMobileNetworkIdentifier' are specified, then the 'publicLandMobileNetworks' will take precedence."]
    #[serde(
        rename = "publicLandMobileNetworks",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub public_land_mobile_networks: Vec<PublicLandMobileNetwork>,
    #[doc = "The mobile network resource identifier"]
    #[serde(rename = "serviceKey", default, skip_serializing_if = "Option::is_none")]
    pub service_key: Option<String>,
}
impl MobileNetworkPropertiesFormat {
    pub fn new(public_land_mobile_network_identifier: PlmnId) -> Self {
        Self {
            provisioning_state: None,
            public_land_mobile_network_identifier,
            public_land_mobile_networks: Vec::new(),
            service_key: None,
        }
    }
}
#[doc = "Reference to a mobile network resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MobileNetworkResourceId {
    #[doc = "Mobile network resource ID."]
    pub id: String,
}
impl MobileNetworkResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "The supported NAS Encryption types."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "NasEncryptionType")]
pub enum NasEncryptionType {
    #[serde(rename = "NEA0/EEA0")]
    Nea0Eea0,
    #[serde(rename = "NEA1/EEA1")]
    Nea1Eea1,
    #[serde(rename = "NEA2/EEA2")]
    Nea2Eea2,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for NasEncryptionType {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for NasEncryptionType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for NasEncryptionType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Nea0Eea0 => serializer.serialize_unit_variant("NasEncryptionType", 0u32, "NEA0/EEA0"),
            Self::Nea1Eea1 => serializer.serialize_unit_variant("NasEncryptionType", 1u32, "NEA1/EEA1"),
            Self::Nea2Eea2 => serializer.serialize_unit_variant("NasEncryptionType", 2u32, "NEA2/EEA2"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Configuration enabling NAS reroute."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NasRerouteConfiguration {
    #[doc = "The macro network's MME group ID. This is where unknown UEs are sent to via NAS reroute."]
    #[serde(rename = "macroMmeGroupId")]
    pub macro_mme_group_id: i32,
}
impl NasRerouteConfiguration {
    pub fn new(macro_mme_group_id: i32) -> Self {
        Self { macro_mme_group_id }
    }
}
#[doc = "The network address and port translation settings to use for the attached data network."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NaptConfiguration {
    #[doc = "Whether network address and port translation is enabled."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<NaptEnabled>,
    #[doc = "Range of port numbers to use as translated ports on each translated address.\nIf not specified and NAPT is enabled, this range defaults to 1,024 - 49,999.\n(Ports under 1,024 should not be used because these are special purpose ports reserved by IANA. Ports 50,000 and above are reserved for non-NAPT use.)"]
    #[serde(rename = "portRange", default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<PortRange>,
    #[doc = "The minimum time (in seconds) that will pass before a port that was used by a closed pinhole can be recycled for use by another pinhole. All hold times must be minimum 1 second."]
    #[serde(rename = "portReuseHoldTime", default, skip_serializing_if = "Option::is_none")]
    pub port_reuse_hold_time: Option<PortReuseHoldTimes>,
    #[doc = "Maximum number of UDP and TCP pinholes that can be open simultaneously on the core interface. For 5G networks, this is the N6 interface. For 4G networks, this is the SGi interface."]
    #[serde(rename = "pinholeLimits", default, skip_serializing_if = "Option::is_none")]
    pub pinhole_limits: Option<i32>,
    #[doc = "Expiry times of inactive NAPT pinholes, in seconds. All timers must be at least 1 second."]
    #[serde(rename = "pinholeTimeouts", default, skip_serializing_if = "Option::is_none")]
    pub pinhole_timeouts: Option<PinholeTimeouts>,
}
impl NaptConfiguration {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Whether network address and port translation is enabled."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "NaptEnabled")]
pub enum NaptEnabled {
    Enabled,
    Disabled,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for NaptEnabled {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for NaptEnabled {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for NaptEnabled {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Enabled => serializer.serialize_unit_variant("NaptEnabled", 0u32, "Enabled"),
            Self::Disabled => serializer.serialize_unit_variant("NaptEnabled", 1u32, "Disabled"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
impl Default for NaptEnabled {
    fn default() -> Self {
        Self::Enabled
    }
}
#[doc = "Indicates whether this version is obsolete."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ObsoleteVersion")]
pub enum ObsoleteVersion {
    Obsolete,
    NotObsolete,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for ObsoleteVersion {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for ObsoleteVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for ObsoleteVersion {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Obsolete => serializer.serialize_unit_variant("ObsoleteVersion", 0u32, "Obsolete"),
            Self::NotObsolete => serializer.serialize_unit_variant("ObsoleteVersion", 1u32, "NotObsolete"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Object that describes a single Microsoft.MobileNetwork operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Operation {
    #[doc = "Indicates whether the operation applies to data-plane."]
    #[serde(rename = "isDataAction", default, skip_serializing_if = "Option::is_none")]
    pub is_data_action: Option<bool>,
    #[doc = "Operation name: {provider}/{resource}/{operation}"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "The object that represents the operation."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<operation::Display>,
}
impl Operation {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod operation {
    use super::*;
    #[doc = "The object that represents the operation."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
    pub struct Display {
        #[doc = "Service provider: Microsoft.MobileNetwork"]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[doc = "Resource on which the operation is performed: Registration definition, registration assignment etc."]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[doc = "Operation type: Read, write, delete, etc."]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operation: Option<String>,
        #[doc = "Description of the operation."]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }
    impl Display {
        pub fn new() -> Self {
            Self::default()
        }
    }
}
#[doc = "List of the operations."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct OperationList {
    #[doc = "List of Microsoft.MobileNetwork operations."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<Operation>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for OperationList {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl OperationList {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Packet capture session resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketCapture {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Packet capture session properties."]
    pub properties: PacketCapturePropertiesFormat,
}
impl PacketCapture {
    pub fn new(properties: PacketCapturePropertiesFormat) -> Self {
        Self {
            proxy_resource: ProxyResource::default(),
            properties,
        }
    }
}
#[doc = "Response for packet capture API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PacketCaptureListResult {
    #[doc = "A list of packet capture sessions under a packet core control plane."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<PacketCapture>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for PacketCaptureListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl PacketCaptureListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Packet capture session properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PacketCapturePropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "The status of the packet capture session."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<packet_capture_properties_format::Status>,
    #[doc = "The reason the current packet capture session state."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[doc = "The start time of the packet capture session."]
    #[serde(rename = "captureStartTime", default, with = "azure_core::date::rfc3339::option")]
    pub capture_start_time: Option<::time::OffsetDateTime>,
    #[doc = "List of network interfaces to capture on."]
    #[serde(
        rename = "networkInterfaces",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_interfaces: Vec<String>,
    #[doc = "Number of bytes captured per packet, the remaining bytes are truncated. The default \"0\" means the entire packet is captured."]
    #[serde(rename = "bytesToCapturePerPacket", default, skip_serializing_if = "Option::is_none")]
    pub bytes_to_capture_per_packet: Option<i64>,
    #[doc = "Maximum size of the capture output."]
    #[serde(rename = "totalBytesPerSession", default, skip_serializing_if = "Option::is_none")]
    pub total_bytes_per_session: Option<i64>,
    #[doc = "Maximum duration of the capture session in seconds."]
    #[serde(rename = "timeLimitInSeconds", default, skip_serializing_if = "Option::is_none")]
    pub time_limit_in_seconds: Option<i32>,
    #[doc = "The list of output files of a packet capture session."]
    #[serde(
        rename = "outputFiles",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub output_files: Vec<String>,
}
impl PacketCapturePropertiesFormat {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod packet_capture_properties_format {
    use super::*;
    #[doc = "The status of the packet capture session."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "Status")]
    pub enum Status {
        NotStarted,
        Running,
        Stopped,
        Error,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for Status {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for Status {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for Status {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::NotStarted => serializer.serialize_unit_variant("Status", 0u32, "NotStarted"),
                Self::Running => serializer.serialize_unit_variant("Status", 1u32, "Running"),
                Self::Stopped => serializer.serialize_unit_variant("Status", 2u32, "Stopped"),
                Self::Error => serializer.serialize_unit_variant("Status", 3u32, "Error"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
}
#[doc = "Packet core control plane resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketCoreControlPlane {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Packet core control plane properties."]
    pub properties: PacketCoreControlPlanePropertiesFormat,
    #[doc = "Managed service identity (User assigned identity)"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ManagedServiceIdentity>,
}
impl PacketCoreControlPlane {
    pub fn new(tracked_resource: TrackedResource, properties: PacketCoreControlPlanePropertiesFormat) -> Self {
        Self {
            tracked_resource,
            properties,
            identity: None,
        }
    }
}
#[doc = "Packet core control plane collect diagnostics package options"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketCoreControlPlaneCollectDiagnosticsPackage {
    #[doc = "The Storage Account Blob URL to upload the diagnostics package to."]
    #[serde(rename = "storageAccountBlobUrl")]
    pub storage_account_blob_url: String,
}
impl PacketCoreControlPlaneCollectDiagnosticsPackage {
    pub fn new(storage_account_blob_url: String) -> Self {
        Self { storage_account_blob_url }
    }
}
#[doc = "Response for packet core control planes API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PacketCoreControlPlaneListResult {
    #[doc = "A list of packet core control planes in a resource group."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<PacketCoreControlPlane>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for PacketCoreControlPlaneListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl PacketCoreControlPlaneListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Packet core control plane properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketCoreControlPlanePropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "The installation state of the packet core."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation: Option<Installation>,
    #[doc = "Site(s) under which this packet core control plane should be deployed. The sites must be in the same location as the packet core control plane."]
    pub sites: Vec<SiteResourceId>,
    #[doc = "The platform where the packet core is deployed."]
    pub platform: PlatformConfiguration,
    #[doc = "The core network technology generation (5G core, EPC / 4G core or EPC / 4G + 5G core)."]
    #[serde(rename = "coreNetworkTechnology", default, skip_serializing_if = "Option::is_none")]
    pub core_network_technology: Option<CoreNetworkType>,
    #[doc = "The desired version of the packet core software."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[doc = "The currently installed version of the packet core software."]
    #[serde(rename = "installedVersion", default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[doc = "The previous version of the packet core software that was deployed. Used when performing the rollback action."]
    #[serde(rename = "rollbackVersion", default, skip_serializing_if = "Option::is_none")]
    pub rollback_version: Option<String>,
    #[doc = "Interface properties"]
    #[serde(rename = "controlPlaneAccessInterface")]
    pub control_plane_access_interface: InterfaceProperties,
    #[doc = "The virtual IP address(es) for the control plane on the access network in a High Availability (HA) system. In an HA deployment the access network router should be configured to anycast traffic for this address to the control plane access interfaces on the active and standby nodes. In non-HA system this list should be omitted or empty."]
    #[serde(
        rename = "controlPlaneAccessVirtualIpv4Addresses",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub control_plane_access_virtual_ipv4_addresses: Vec<Ipv4Addr>,
    #[doc = "The SKU of the packet core control plane resource. The SKU list may change over time when a new SKU gets added or an exiting SKU gets removed."]
    pub sku: BillingSku,
    #[doc = "The MTU (in bytes) signaled to the UE. The same MTU is set on the user plane data links for all data networks. The MTU set on the user plane access link is calculated to be 60 bytes greater than this value to allow for GTP encapsulation."]
    #[serde(rename = "ueMtu", default, skip_serializing_if = "Option::is_none")]
    pub ue_mtu: Option<i32>,
    #[doc = "The kubernetes ingress configuration to control access to packet core diagnostics over local APIs."]
    #[serde(rename = "localDiagnosticsAccess")]
    pub local_diagnostics_access: LocalDiagnosticsAccessConfiguration,
    #[doc = "Configuration for uploading packet core diagnostics."]
    #[serde(rename = "diagnosticsUpload", default, skip_serializing_if = "Option::is_none")]
    pub diagnostics_upload: Option<DiagnosticsUploadConfiguration>,
    #[doc = "Configuration for sending packet core events to Azure Event Hub."]
    #[serde(rename = "eventHub", default, skip_serializing_if = "Option::is_none")]
    pub event_hub: Option<EventHubConfiguration>,
    #[doc = "Signaling configuration for the packet core."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signaling: Option<SignalingConfiguration>,
    #[doc = "Settings to allow interoperability with third party components e.g. RANs and UEs."]
    #[serde(rename = "interopSettings", default, skip_serializing_if = "Option::is_none")]
    pub interop_settings: Option<serde_json::Value>,
    #[serde(rename = "homeNetworkPrivateKeysProvisioning", default, skip_serializing_if = "Option::is_none")]
    pub home_network_private_keys_provisioning: Option<HomeNetworkPrivateKeysProvisioning>,
    #[serde(rename = "userConsent", default, skip_serializing_if = "Option::is_none")]
    pub user_consent: Option<UserConsentConfiguration>,
}
impl PacketCoreControlPlanePropertiesFormat {
    pub fn new(
        sites: Vec<SiteResourceId>,
        platform: PlatformConfiguration,
        control_plane_access_interface: InterfaceProperties,
        sku: BillingSku,
        local_diagnostics_access: LocalDiagnosticsAccessConfiguration,
    ) -> Self {
        Self {
            provisioning_state: None,
            installation: None,
            sites,
            platform,
            core_network_technology: None,
            version: None,
            installed_version: None,
            rollback_version: None,
            control_plane_access_interface,
            control_plane_access_virtual_ipv4_addresses: Vec::new(),
            sku,
            ue_mtu: None,
            local_diagnostics_access,
            diagnostics_upload: None,
            event_hub: None,
            signaling: None,
            interop_settings: None,
            home_network_private_keys_provisioning: None,
            user_consent: None,
        }
    }
}
#[doc = "Reference to an packet core control plane resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketCoreControlPlaneResourceId {
    #[doc = "Packet core control plane resource ID."]
    pub id: String,
}
impl PacketCoreControlPlaneResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "Packet core control plane version resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketCoreControlPlaneVersion {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Packet core control plane version properties."]
    pub properties: PacketCoreControlPlaneVersionPropertiesFormat,
}
impl PacketCoreControlPlaneVersion {
    pub fn new(properties: PacketCoreControlPlaneVersionPropertiesFormat) -> Self {
        Self {
            proxy_resource: ProxyResource::default(),
            properties,
        }
    }
}
#[doc = "Response for packet core control plane version API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PacketCoreControlPlaneVersionListResult {
    #[doc = "A list of supported packet core control plane versions."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<PacketCoreControlPlaneVersion>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for PacketCoreControlPlaneVersionListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl PacketCoreControlPlaneVersionListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Packet core control plane version properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PacketCoreControlPlaneVersionPropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "Platform specific packet core control plane version properties."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub platforms: Vec<Platform>,
}
impl PacketCoreControlPlaneVersionPropertiesFormat {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Packet core data plane resource. Must be created in the same location as its parent packet core control plane."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketCoreDataPlane {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Packet core data plane properties."]
    pub properties: PacketCoreDataPlanePropertiesFormat,
}
impl PacketCoreDataPlane {
    pub fn new(tracked_resource: TrackedResource, properties: PacketCoreDataPlanePropertiesFormat) -> Self {
        Self {
            tracked_resource,
            properties,
        }
    }
}
#[doc = "Response for packet core data planes API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PacketCoreDataPlaneListResult {
    #[doc = "A list of packet core data planes in a resource group."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<PacketCoreDataPlane>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for PacketCoreDataPlaneListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl PacketCoreDataPlaneListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Packet core data plane properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketCoreDataPlanePropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "Interface properties"]
    #[serde(rename = "userPlaneAccessInterface")]
    pub user_plane_access_interface: InterfaceProperties,
    #[doc = "The virtual IP address(es) for the user plane on the access network in a High Availability (HA) system. In an HA deployment the access network router should be configured to forward traffic for this address to the control plane access interface on the active or standby node. In non-HA system this list should be omitted or empty."]
    #[serde(
        rename = "userPlaneAccessVirtualIpv4Addresses",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub user_plane_access_virtual_ipv4_addresses: Vec<Ipv4Addr>,
}
impl PacketCoreDataPlanePropertiesFormat {
    pub fn new(user_plane_access_interface: InterfaceProperties) -> Self {
        Self {
            provisioning_state: None,
            user_plane_access_interface,
            user_plane_access_virtual_ipv4_addresses: Vec::new(),
        }
    }
}
#[doc = "Data flow policy rule configuration"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PccRuleConfiguration {
    #[doc = "The name of the rule. This must be unique within the parent service. You must not use any of the following reserved strings - `default`, `requested` or `service`."]
    #[serde(rename = "ruleName")]
    pub rule_name: String,
    #[doc = "A precedence value that is used to decide between data flow policy rules when identifying the QoS values to use for a particular SIM. A lower value means a higher priority. This value should be unique among all data flow policy rules configured in the mobile network."]
    #[serde(rename = "rulePrecedence")]
    pub rule_precedence: i32,
    #[doc = "Data flow policy rule QoS policy"]
    #[serde(rename = "ruleQosPolicy", default, skip_serializing_if = "Option::is_none")]
    pub rule_qos_policy: Option<PccRuleQosPolicy>,
    #[doc = "Traffic control permission."]
    #[serde(rename = "trafficControl", default, skip_serializing_if = "Option::is_none")]
    pub traffic_control: Option<TrafficControlPermission>,
    #[doc = "The set of data flow templates to use for this data flow policy rule."]
    #[serde(rename = "serviceDataFlowTemplates")]
    pub service_data_flow_templates: Vec<ServiceDataFlowTemplate>,
}
impl PccRuleConfiguration {
    pub fn new(rule_name: String, rule_precedence: i32, service_data_flow_templates: Vec<ServiceDataFlowTemplate>) -> Self {
        Self {
            rule_name,
            rule_precedence,
            rule_qos_policy: None,
            traffic_control: None,
            service_data_flow_templates,
        }
    }
}
#[doc = "Data flow policy rule QoS policy"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PccRuleQosPolicy {
    #[serde(flatten)]
    pub qos_policy: QosPolicy,
    #[doc = "Aggregate maximum bit rate."]
    #[serde(rename = "guaranteedBitRate", default, skip_serializing_if = "Option::is_none")]
    pub guaranteed_bit_rate: Option<Ambr>,
}
impl PccRuleQosPolicy {
    pub fn new(qos_policy: QosPolicy) -> Self {
        Self {
            qos_policy,
            guaranteed_bit_rate: None,
        }
    }
}
#[doc = "Packet Data Network Type"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "PdnType")]
pub enum PdnType {
    #[serde(rename = "IPV4")]
    Ipv4,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for PdnType {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for PdnType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for PdnType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Ipv4 => serializer.serialize_unit_variant("PdnType", 0u32, "IPV4"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
pub type PduSessionId = i32;
#[doc = "PDU session type (IPv4/IPv6)."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "PduSessionType")]
pub enum PduSessionType {
    IPv4,
    IPv6,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for PduSessionType {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for PduSessionType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for PduSessionType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::IPv4 => serializer.serialize_unit_variant("PduSessionType", 0u32, "IPv4"),
            Self::IPv6 => serializer.serialize_unit_variant("PduSessionType", 1u32, "IPv6"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "PDU session type (IPv4/IPv6)."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "PduSessionTypeRm")]
pub enum PduSessionTypeRm {
    IPv4,
    IPv6,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for PduSessionTypeRm {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for PduSessionTypeRm {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for PduSessionTypeRm {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::IPv4 => serializer.serialize_unit_variant("PduSessionTypeRm", 0u32, "IPv4"),
            Self::IPv6 => serializer.serialize_unit_variant("PduSessionTypeRm", 1u32, "IPv6"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
pub type Pei = String;
#[doc = "Expiry times of inactive NAPT pinholes, in seconds. All timers must be at least 1 second."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PinholeTimeouts {
    #[doc = "Pinhole timeout for TCP pinholes in seconds. Default for TCP is 3 minutes."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<i32>,
    #[doc = "Pinhole timeout for UDP pinholes in seconds. Default for UDP is 30 seconds."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<i32>,
    #[doc = "Pinhole timeout for ICMP pinholes in seconds. Default for ICMP Echo is 30 seconds."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp: Option<i32>,
}
impl PinholeTimeouts {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Platform specific packet core control plane version properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Platform {
    #[doc = "The platform type where packet core is deployed. The contents of this enum can change."]
    #[serde(rename = "platformType", default, skip_serializing_if = "Option::is_none")]
    pub platform_type: Option<PlatformType>,
    #[doc = "The state of this packet core control plane version."]
    #[serde(rename = "versionState", default, skip_serializing_if = "Option::is_none")]
    pub version_state: Option<VersionState>,
    #[doc = "The minimum software version of the platform where this packet core version can be deployed."]
    #[serde(rename = "minimumPlatformSoftwareVersion", default, skip_serializing_if = "Option::is_none")]
    pub minimum_platform_software_version: Option<String>,
    #[doc = "The maximum software version of the platform where this packet core version can be deployed."]
    #[serde(rename = "maximumPlatformSoftwareVersion", default, skip_serializing_if = "Option::is_none")]
    pub maximum_platform_software_version: Option<String>,
    #[doc = "Indicates whether this is the recommended version to use for new packet core control plane deployments."]
    #[serde(rename = "recommendedVersion", default, skip_serializing_if = "Option::is_none")]
    pub recommended_version: Option<RecommendedVersion>,
    #[doc = "Indicates whether this version is obsolete."]
    #[serde(rename = "obsoleteVersion", default, skip_serializing_if = "Option::is_none")]
    pub obsolete_version: Option<ObsoleteVersion>,
    #[doc = "The list of versions to which a high availability upgrade from this version is supported."]
    #[serde(
        rename = "haUpgradesAvailable",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ha_upgrades_available: Vec<String>,
}
impl Platform {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The platform where the packet core is deployed."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlatformConfiguration {
    #[doc = "The platform type where packet core is deployed. The contents of this enum can change."]
    #[serde(rename = "type")]
    pub type_: PlatformType,
    #[doc = "Reference to an Azure Stack Edge device resource."]
    #[serde(rename = "azureStackEdgeDevice", default, skip_serializing_if = "Option::is_none")]
    pub azure_stack_edge_device: Option<AzureStackEdgeDeviceResourceId>,
    #[doc = "The Azure Stack Edge devices where the packet core is deployed. If the packet core is deployed across multiple devices, all devices will appear in this list."]
    #[serde(
        rename = "azureStackEdgeDevices",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub azure_stack_edge_devices: Vec<AzureStackEdgeDeviceResourceId>,
    #[doc = "Reference to an Azure Stack HCI cluster resource."]
    #[serde(rename = "azureStackHciCluster", default, skip_serializing_if = "Option::is_none")]
    pub azure_stack_hci_cluster: Option<AzureStackHciClusterResourceId>,
    #[doc = "Reference to an Azure Arc custom location resource."]
    #[serde(rename = "connectedCluster", default, skip_serializing_if = "Option::is_none")]
    pub connected_cluster: Option<ConnectedClusterResourceId>,
    #[doc = "Reference to an Azure Arc custom location resource."]
    #[serde(rename = "customLocation", default, skip_serializing_if = "Option::is_none")]
    pub custom_location: Option<CustomLocationResourceId>,
}
impl PlatformConfiguration {
    pub fn new(type_: PlatformType) -> Self {
        Self {
            type_,
            azure_stack_edge_device: None,
            azure_stack_edge_devices: Vec::new(),
            azure_stack_hci_cluster: None,
            connected_cluster: None,
            custom_location: None,
        }
    }
}
#[doc = "The platform type where packet core is deployed. The contents of this enum can change."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "PlatformType")]
pub enum PlatformType {
    #[serde(rename = "AKS-HCI")]
    AksHci,
    #[serde(rename = "3P-AZURE-STACK-HCI")]
    N3P_AZURE_STACK_HCI,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for PlatformType {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for PlatformType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for PlatformType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::AksHci => serializer.serialize_unit_variant("PlatformType", 0u32, "AKS-HCI"),
            Self::N3P_AZURE_STACK_HCI => serializer.serialize_unit_variant("PlatformType", 1u32, "3P-AZURE-STACK-HCI"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Public land mobile network (PLMN) ID. This is made up of the mobile country code and mobile network code, as defined in https://www.itu.int/rec/T-REC-E.212. The values 001-01 and 001-001 can be used for testing and the values 999-99 and 999-999 can be used on internal private networks."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlmnId {
    #[doc = "Mobile country code."]
    pub mcc: Mcc,
    #[doc = "Mobile network code."]
    pub mnc: Mnc,
}
impl PlmnId {
    pub fn new(mcc: Mcc, mnc: Mnc) -> Self {
        Self { mcc, mnc }
    }
}
#[doc = "Public land mobile network (PLMN) ID. This is made up of the mobile country code and mobile network code, as defined in https://www.itu.int/rec/T-REC-E.212. The values 001-01 and 001-001 can be used for testing and the values 999-99 and 999-999 can be used on internal private networks."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlmnIdRm {
    #[doc = "Mobile country code."]
    pub mcc: Mcc,
    #[doc = "Mobile network code."]
    pub mnc: Mnc,
}
impl PlmnIdRm {
    pub fn new(mcc: Mcc, mnc: Mnc) -> Self {
        Self { mcc, mnc }
    }
}
#[doc = "Range of port numbers to use as translated ports on each translated address.\nIf not specified and NAPT is enabled, this range defaults to 1,024 - 49,999.\n(Ports under 1,024 should not be used because these are special purpose ports reserved by IANA. Ports 50,000 and above are reserved for non-NAPT use.)"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PortRange {
    #[doc = "The minimum port number"]
    #[serde(rename = "minPort", default, skip_serializing_if = "Option::is_none")]
    pub min_port: Option<i32>,
    #[doc = "The maximum port number"]
    #[serde(rename = "maxPort", default, skip_serializing_if = "Option::is_none")]
    pub max_port: Option<i32>,
}
impl PortRange {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The minimum time (in seconds) that will pass before a port that was used by a closed pinhole can be recycled for use by another pinhole. All hold times must be minimum 1 second."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PortReuseHoldTimes {
    #[doc = "Minimum time in seconds that will pass before a TCP port that was used by a closed pinhole can be reused. Default for TCP is 2 minutes."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<i32>,
    #[doc = "Minimum time in seconds that will pass before a UDP port that was used by a closed pinhole can be reused. Default for UDP is 1 minute."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<i32>,
}
impl PortReuseHoldTimes {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Preemption capability."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "PreemptionCapability")]
pub enum PreemptionCapability {
    NotPreempt,
    MayPreempt,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for PreemptionCapability {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for PreemptionCapability {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for PreemptionCapability {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::NotPreempt => serializer.serialize_unit_variant("PreemptionCapability", 0u32, "NotPreempt"),
            Self::MayPreempt => serializer.serialize_unit_variant("PreemptionCapability", 1u32, "MayPreempt"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Preemption vulnerability."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "PreemptionVulnerability")]
pub enum PreemptionVulnerability {
    NotPreemptable,
    Preemptable,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for PreemptionVulnerability {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for PreemptionVulnerability {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for PreemptionVulnerability {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::NotPreemptable => serializer.serialize_unit_variant("PreemptionVulnerability", 0u32, "NotPreemptable"),
            Self::Preemptable => serializer.serialize_unit_variant("PreemptionVulnerability", 1u32, "Preemptable"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "The current provisioning state."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ProvisioningState")]
pub enum ProvisioningState {
    Unknown,
    Succeeded,
    Accepted,
    Deleting,
    Failed,
    Canceled,
    Deleted,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for ProvisioningState {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for ProvisioningState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for ProvisioningState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Unknown => serializer.serialize_unit_variant("ProvisioningState", 0u32, "Unknown"),
            Self::Succeeded => serializer.serialize_unit_variant("ProvisioningState", 1u32, "Succeeded"),
            Self::Accepted => serializer.serialize_unit_variant("ProvisioningState", 2u32, "Accepted"),
            Self::Deleting => serializer.serialize_unit_variant("ProvisioningState", 3u32, "Deleting"),
            Self::Failed => serializer.serialize_unit_variant("ProvisioningState", 4u32, "Failed"),
            Self::Canceled => serializer.serialize_unit_variant("ProvisioningState", 5u32, "Canceled"),
            Self::Deleted => serializer.serialize_unit_variant("ProvisioningState", 6u32, "Deleted"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "The resource model definition for a Azure Resource Manager proxy resource. It will not have tags and a location"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ProxyResource {
    #[serde(flatten)]
    pub resource: Resource,
}
impl ProxyResource {
    pub fn new() -> Self {
        Self::default()
    }
}
pub type Qfi = i32;
#[doc = "QoS policy"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QosPolicy {
    #[doc = "5G QoS Identifier priority level."]
    #[serde(rename = "5qi", default, skip_serializing_if = "Option::is_none")]
    pub n5qi: Option<N5QiPriorityLevel>,
    #[doc = "ARP priority level."]
    #[serde(rename = "allocationAndRetentionPriorityLevel", default, skip_serializing_if = "Option::is_none")]
    pub allocation_and_retention_priority_level: Option<ArpPriorityLevel>,
    #[doc = "Preemption capability."]
    #[serde(rename = "preemptionCapability", default, skip_serializing_if = "Option::is_none")]
    pub preemption_capability: Option<PreemptionCapability>,
    #[doc = "Preemption vulnerability."]
    #[serde(rename = "preemptionVulnerability", default, skip_serializing_if = "Option::is_none")]
    pub preemption_vulnerability: Option<PreemptionVulnerability>,
    #[doc = "Aggregate maximum bit rate."]
    #[serde(rename = "maximumBitRate")]
    pub maximum_bit_rate: Ambr,
}
impl QosPolicy {
    pub fn new(maximum_bit_rate: Ambr) -> Self {
        Self {
            n5qi: None,
            allocation_and_retention_priority_level: None,
            preemption_capability: None,
            preemption_vulnerability: None,
            maximum_bit_rate,
        }
    }
}
#[doc = "RAT Type"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "RatType")]
pub enum RatType {
    #[serde(rename = "4G")]
    N4G,
    #[serde(rename = "5G")]
    N5G,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for RatType {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for RatType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for RatType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::N4G => serializer.serialize_unit_variant("RatType", 0u32, "4G"),
            Self::N5G => serializer.serialize_unit_variant("RatType", 1u32, "5G"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Indicates whether this is the recommended version to use for new packet core control plane deployments."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "RecommendedVersion")]
pub enum RecommendedVersion {
    Recommended,
    NotRecommended,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for RecommendedVersion {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for RecommendedVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for RecommendedVersion {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Recommended => serializer.serialize_unit_variant("RecommendedVersion", 0u32, "Recommended"),
            Self::NotRecommended => serializer.serialize_unit_variant("RecommendedVersion", 1u32, "NotRecommended"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Whether a reinstall of the packet core is required to pick up the latest configuration changes."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ReinstallRequired")]
pub enum ReinstallRequired {
    Required,
    NotRequired,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for ReinstallRequired {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for ReinstallRequired {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for ReinstallRequired {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Required => serializer.serialize_unit_variant("ReinstallRequired", 0u32, "Required"),
            Self::NotRequired => serializer.serialize_unit_variant("ReinstallRequired", 1u32, "NotRequired"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Common fields that are returned in the response for all Azure Resource Manager resources"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Resource {
    #[doc = "Fully qualified resource ID for the resource. E.g. \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\""]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[doc = "The name of the resource"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "The type of the resource. E.g. \"Microsoft.Compute/virtualMachines\" or \"Microsoft.Storage/storageAccounts\""]
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[doc = "Metadata pertaining to creation and last modification of the resource."]
    #[serde(rename = "systemData", default, skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}
impl Resource {
    pub fn new() -> Self {
        Self::default()
    }
}
pub type RfspIndex = i32;
pub type RfspIndexRm = i32;
#[doc = "Response for the list routing information API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct RoutingInfoListResult {
    #[doc = "A list of the routing information for the packet core control plane"]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<RoutingInfoModel>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for RoutingInfoListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl RoutingInfoListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Routing information"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoutingInfoModel {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Routing information properties"]
    pub properties: RoutingInfoPropertiesFormat,
}
impl RoutingInfoModel {
    pub fn new(properties: RoutingInfoPropertiesFormat) -> Self {
        Self {
            proxy_resource: ProxyResource::default(),
            properties,
        }
    }
}
#[doc = "Routing information properties"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct RoutingInfoPropertiesFormat {
    #[doc = "A list of IPv4 routes."]
    #[serde(rename = "controlPlaneAccessRoutes", default, skip_serializing_if = "Option::is_none")]
    pub control_plane_access_routes: Option<Ipv4Routes>,
    #[doc = "A list of IPv4 routes."]
    #[serde(rename = "userPlaneAccessRoutes", default, skip_serializing_if = "Option::is_none")]
    pub user_plane_access_routes: Option<Ipv4Routes>,
    #[doc = "A list of attached data networks and their IPv4 routes."]
    #[serde(rename = "userPlaneDataRoutes", default, skip_serializing_if = "Option::is_none")]
    pub user_plane_data_routes: Option<UserPlaneDataRoutes>,
}
impl RoutingInfoPropertiesFormat {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Radio connection establishment cause"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "RrcEstablishmentCause")]
pub enum RrcEstablishmentCause {
    Emergency,
    MobileOriginatedSignaling,
    MobileTerminatedSignaling,
    MobileOriginatedData,
    MobileTerminatedData,
    #[serde(rename = "SMS")]
    Sms,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for RrcEstablishmentCause {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for RrcEstablishmentCause {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for RrcEstablishmentCause {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Emergency => serializer.serialize_unit_variant("RrcEstablishmentCause", 0u32, "Emergency"),
            Self::MobileOriginatedSignaling => {
                serializer.serialize_unit_variant("RrcEstablishmentCause", 1u32, "MobileOriginatedSignaling")
            }
            Self::MobileTerminatedSignaling => {
                serializer.serialize_unit_variant("RrcEstablishmentCause", 2u32, "MobileTerminatedSignaling")
            }
            Self::MobileOriginatedData => serializer.serialize_unit_variant("RrcEstablishmentCause", 3u32, "MobileOriginatedData"),
            Self::MobileTerminatedData => serializer.serialize_unit_variant("RrcEstablishmentCause", 4u32, "MobileTerminatedData"),
            Self::Sms => serializer.serialize_unit_variant("RrcEstablishmentCause", 5u32, "SMS"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Service data flow direction."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "SdfDirection")]
pub enum SdfDirection {
    Uplink,
    Downlink,
    Bidirectional,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for SdfDirection {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for SdfDirection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for SdfDirection {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Uplink => serializer.serialize_unit_variant("SdfDirection", 0u32, "Uplink"),
            Self::Downlink => serializer.serialize_unit_variant("SdfDirection", 1u32, "Downlink"),
            Self::Bidirectional => serializer.serialize_unit_variant("SdfDirection", 2u32, "Bidirectional"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Service resource. Must be created in the same location as its parent mobile network."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Service {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Service properties."]
    pub properties: ServicePropertiesFormat,
}
impl Service {
    pub fn new(tracked_resource: TrackedResource, properties: ServicePropertiesFormat) -> Self {
        Self {
            tracked_resource,
            properties,
        }
    }
}
#[doc = "Data flow template"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceDataFlowTemplate {
    #[doc = "The name of the data flow template. This must be unique within the parent data flow policy rule. You must not use any of the following reserved strings - `default`, `requested` or `service`."]
    #[serde(rename = "templateName")]
    pub template_name: String,
    #[doc = "Service data flow direction."]
    pub direction: SdfDirection,
    #[doc = "A list of the allowed protocol(s) for this flow. If you want this flow to be able to use any protocol within the internet protocol suite, use the value `ip`. If you only want to allow a selection of protocols, you must use the corresponding IANA Assigned Internet Protocol Number for each protocol, as described in https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml. For example, for UDP, you must use 17. If you use the value `ip` then you must leave the field `port` unspecified."]
    pub protocol: Vec<String>,
    #[doc = "The remote IP address(es) to which UEs will connect for this flow. If you want to allow connections on any IP address, use the value `any`. Otherwise, you must provide each of the remote IP addresses to which the packet core instance will connect for this flow. You must provide each IP address in CIDR notation, including the netmask (for example, 192.0.2.54/24)."]
    #[serde(rename = "remoteIpList")]
    pub remote_ip_list: Vec<String>,
    #[doc = "The port(s) to which UEs will connect for this flow. You can specify zero or more ports or port ranges. If you specify one or more ports or port ranges then you must specify a value other than `ip` in the `protocol` field. This is an optional setting. If you do not specify it then connections will be allowed on all ports. Port ranges must be specified as <FirstPort>-<LastPort>. For example: [`8080`, `8082-8085`]."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ports: Vec<String>,
}
impl ServiceDataFlowTemplate {
    pub fn new(template_name: String, direction: SdfDirection, protocol: Vec<String>, remote_ip_list: Vec<String>) -> Self {
        Self {
            template_name,
            direction,
            protocol,
            remote_ip_list,
            ports: Vec::new(),
        }
    }
}
#[doc = "Response for services API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ServiceListResult {
    #[doc = "A list of services."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<Service>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for ServiceListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl ServiceListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Service properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServicePropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "A precedence value that is used to decide between services when identifying the QoS values to use for a particular SIM. A lower value means a higher priority. This value should be unique among all services configured in the mobile network."]
    #[serde(rename = "servicePrecedence")]
    pub service_precedence: i32,
    #[doc = "QoS policy"]
    #[serde(rename = "serviceQosPolicy", default, skip_serializing_if = "Option::is_none")]
    pub service_qos_policy: Option<QosPolicy>,
    #[doc = "The set of data flow policy rules that make up this service."]
    #[serde(rename = "pccRules")]
    pub pcc_rules: Vec<PccRuleConfiguration>,
}
impl ServicePropertiesFormat {
    pub fn new(service_precedence: i32, pcc_rules: Vec<PccRuleConfiguration>) -> Self {
        Self {
            provisioning_state: None,
            service_precedence,
            service_qos_policy: None,
            pcc_rules,
        }
    }
}
#[doc = "Reference to a service resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceResourceId {
    #[doc = "Service resource ID."]
    pub id: String,
}
impl ServiceResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "Signaling configuration for the packet core."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SignalingConfiguration {
    #[doc = "Configuration enabling NAS reroute."]
    #[serde(rename = "nasReroute", default, skip_serializing_if = "Option::is_none")]
    pub nas_reroute: Option<NasRerouteConfiguration>,
    #[doc = "An ordered list of NAS encryption algorithms, used to encrypt control plane traffic between the UE and packet core, in order from most to least preferred. If not specified, the packet core will use a built-in default ordering."]
    #[serde(
        rename = "nasEncryption",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub nas_encryption: Vec<NasEncryptionType>,
}
impl SignalingConfiguration {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "SIM resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sim {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "SIM properties."]
    pub properties: SimPropertiesFormat,
}
impl Sim {
    pub fn new(properties: SimPropertiesFormat) -> Self {
        Self {
            proxy_resource: ProxyResource::default(),
            properties,
        }
    }
}
#[doc = "The SIMs to clone."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SimClone {
    #[doc = "Reference to a SIM group resource."]
    #[serde(rename = "targetSimGroupId", default, skip_serializing_if = "Option::is_none")]
    pub target_sim_group_id: Option<SimGroupResourceId>,
    #[doc = "A list of SIM resource names to be cloned."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub sims: Vec<SimName>,
}
impl SimClone {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The SIMs to delete."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimDeleteList {
    #[doc = "A list of SIM resource names to delete."]
    pub sims: Vec<String>,
}
impl SimDeleteList {
    pub fn new(sims: Vec<String>) -> Self {
        Self { sims }
    }
}
#[doc = "SIM group resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimGroup {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "SIM group properties."]
    pub properties: SimGroupPropertiesFormat,
    #[doc = "Managed service identity (User assigned identity)"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ManagedServiceIdentity>,
}
impl SimGroup {
    pub fn new(tracked_resource: TrackedResource, properties: SimGroupPropertiesFormat) -> Self {
        Self {
            tracked_resource,
            properties,
            identity: None,
        }
    }
}
#[doc = "Response for list SIM groups API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SimGroupListResult {
    #[doc = "A list of SIM groups in a resource group."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<SimGroup>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for SimGroupListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl SimGroupListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "SIM group properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SimGroupPropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "An Azure key vault key."]
    #[serde(rename = "encryptionKey", default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<KeyVaultKey>,
    #[doc = "Reference to a mobile network resource."]
    #[serde(rename = "mobileNetwork", default, skip_serializing_if = "Option::is_none")]
    pub mobile_network: Option<MobileNetworkResourceId>,
}
impl SimGroupPropertiesFormat {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Reference to a SIM group resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimGroupResourceId {
    #[doc = "SIM group resource ID."]
    pub id: String,
}
impl SimGroupResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "Response for list SIMs API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SimListResult {
    #[doc = "A list of SIMs in a resource group."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<Sim>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for SimListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl SimListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The SIMs to move."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SimMove {
    #[doc = "Reference to a SIM group resource."]
    #[serde(rename = "targetSimGroupId", default, skip_serializing_if = "Option::is_none")]
    pub target_sim_group_id: Option<SimGroupResourceId>,
    #[doc = "A list of SIM resource names to be moved."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub sims: Vec<SimName>,
}
impl SimMove {
    pub fn new() -> Self {
        Self::default()
    }
}
pub type SimName = String;
#[doc = "SIM name and encrypted properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimNameAndEncryptedProperties {
    #[doc = "The name of the SIM."]
    pub name: String,
    #[doc = "Encrypted SIM properties."]
    pub properties: EncryptedSimPropertiesFormat,
}
impl SimNameAndEncryptedProperties {
    pub fn new(name: String, properties: EncryptedSimPropertiesFormat) -> Self {
        Self { name, properties }
    }
}
#[doc = "SIM name and properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimNameAndProperties {
    #[doc = "The name of the SIM."]
    pub name: String,
    #[doc = "SIM properties."]
    pub properties: SimPropertiesFormat,
}
impl SimNameAndProperties {
    pub fn new(name: String, properties: SimPropertiesFormat) -> Self {
        Self { name, properties }
    }
}
#[doc = "SIM policy resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimPolicy {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "SIM policy properties. Must be created in the same location as its parent mobile network."]
    pub properties: SimPolicyPropertiesFormat,
}
impl SimPolicy {
    pub fn new(tracked_resource: TrackedResource, properties: SimPolicyPropertiesFormat) -> Self {
        Self {
            tracked_resource,
            properties,
        }
    }
}
#[doc = "Response for SIM policies API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SimPolicyListResult {
    #[doc = "A list of SIM policies."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<SimPolicy>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for SimPolicyListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl SimPolicyListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "SIM policy properties. Must be created in the same location as its parent mobile network."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimPolicyPropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "The provisioning state of a resource e.g. SIM/SIM policy on a site. The dictionary keys will ARM resource IDs in the form: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MobileNetwork/mobileNetworks/{mobileNetworkName}/sites/{siteName}. The dictionary values will be from the \"SiteProvisioningState\" enum."]
    #[serde(rename = "siteProvisioningState", default, skip_serializing_if = "Option::is_none")]
    pub site_provisioning_state: Option<SiteProvisioning>,
    #[doc = "Aggregate maximum bit rate."]
    #[serde(rename = "ueAmbr")]
    pub ue_ambr: Ambr,
    #[doc = "Reference to a slice resource."]
    #[serde(rename = "defaultSlice")]
    pub default_slice: SliceResourceId,
    #[doc = "RAT/Frequency Selection Priority Index"]
    #[serde(rename = "rfspIndex", default, skip_serializing_if = "Option::is_none")]
    pub rfsp_index: Option<RfspIndex>,
    #[doc = "UE periodic registration update timer (5G) or UE periodic tracking area update timer (4G), in seconds."]
    #[serde(rename = "registrationTimer", default, skip_serializing_if = "Option::is_none")]
    pub registration_timer: Option<i32>,
    #[doc = "The allowed slices and the settings to use for them. The list must not contain duplicate items and must contain at least one item."]
    #[serde(rename = "sliceConfigurations")]
    pub slice_configurations: Vec<SliceConfiguration>,
}
impl SimPolicyPropertiesFormat {
    pub fn new(ue_ambr: Ambr, default_slice: SliceResourceId, slice_configurations: Vec<SliceConfiguration>) -> Self {
        Self {
            provisioning_state: None,
            site_provisioning_state: None,
            ue_ambr,
            default_slice,
            rfsp_index: None,
            registration_timer: None,
            slice_configurations,
        }
    }
}
#[doc = "Reference to a SIM policy resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimPolicyResourceId {
    #[doc = "SIM policy resource ID."]
    pub id: String,
}
impl SimPolicyResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "SIM properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimPropertiesFormat {
    #[serde(flatten)]
    pub common_sim_properties_format: CommonSimPropertiesFormat,
    #[doc = "The Ki value for the SIM."]
    #[serde(rename = "authenticationKey", default, skip_serializing_if = "Option::is_none")]
    pub authentication_key: Option<String>,
    #[doc = "The Opc value for the SIM."]
    #[serde(rename = "operatorKeyCode", default, skip_serializing_if = "Option::is_none")]
    pub operator_key_code: Option<String>,
}
impl SimPropertiesFormat {
    pub fn new(common_sim_properties_format: CommonSimPropertiesFormat) -> Self {
        Self {
            common_sim_properties_format,
            authentication_key: None,
            operator_key_code: None,
        }
    }
}
#[doc = "The state of the SIM resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "SimState")]
pub enum SimState {
    Disabled,
    Enabled,
    Invalid,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for SimState {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for SimState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for SimState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Disabled => serializer.serialize_unit_variant("SimState", 0u32, "Disabled"),
            Self::Enabled => serializer.serialize_unit_variant("SimState", 1u32, "Enabled"),
            Self::Invalid => serializer.serialize_unit_variant("SimState", 2u32, "Invalid"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Static IP configuration for a SIM, scoped to a particular attached data network and slice."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SimStaticIpProperties {
    #[doc = "Reference to an attached data network resource."]
    #[serde(rename = "attachedDataNetwork", default, skip_serializing_if = "Option::is_none")]
    pub attached_data_network: Option<AttachedDataNetworkResourceId>,
    #[doc = "Reference to a slice resource."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<SliceResourceId>,
    #[doc = "The static IP configuration for the SIM to use at the defined network scope."]
    #[serde(rename = "staticIp", default, skip_serializing_if = "Option::is_none")]
    pub static_ip: Option<sim_static_ip_properties::StaticIp>,
}
impl SimStaticIpProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod sim_static_ip_properties {
    use super::*;
    #[doc = "The static IP configuration for the SIM to use at the defined network scope."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
    pub struct StaticIp {
        #[doc = "IPv4 address."]
        #[serde(rename = "ipv4Address", default, skip_serializing_if = "Option::is_none")]
        pub ipv4_address: Option<Ipv4Addr>,
    }
    impl StaticIp {
        pub fn new() -> Self {
            Self::default()
        }
    }
}
#[doc = "The SIMs to upload."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimUploadList {
    #[doc = "A list of SIMs to upload."]
    pub sims: Vec<SimNameAndProperties>,
}
impl SimUploadList {
    pub fn new(sims: Vec<SimNameAndProperties>) -> Self {
        Self { sims }
    }
}
#[doc = "Site resource. Must be created in the same location as its parent mobile network."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Site {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Site properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<SitePropertiesFormat>,
}
impl Site {
    pub fn new(tracked_resource: TrackedResource) -> Self {
        Self {
            tracked_resource,
            properties: None,
        }
    }
}
#[doc = "The packet core to delete under a site."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SiteDeletePacketCore {
    #[doc = "Reference to an packet core control plane resource."]
    #[serde(rename = "packetCore", default, skip_serializing_if = "Option::is_none")]
    pub packet_core: Option<PacketCoreControlPlaneResourceId>,
}
impl SiteDeletePacketCore {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Response for sites API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SiteListResult {
    #[doc = "A list of sites in a mobile network."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<Site>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for SiteListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl SiteListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Site properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SitePropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "An array of IDs of the network functions deployed in the site. Deleting the site will delete any network functions that are deployed in the site."]
    #[serde(
        rename = "networkFunctions",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_functions: Vec<SubResource>,
}
impl SitePropertiesFormat {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The provisioning state of a resource e.g. SIM/SIM policy on a site. The dictionary keys will ARM resource IDs in the form: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MobileNetwork/mobileNetworks/{mobileNetworkName}/sites/{siteName}. The dictionary values will be from the \"SiteProvisioningState\" enum."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SiteProvisioning {}
impl SiteProvisioning {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The provisioning state of a resource e.g. SIM/SIM policy on a site."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "SiteProvisioningState")]
pub enum SiteProvisioningState {
    NotApplicable,
    Adding,
    Updating,
    Deleting,
    Provisioned,
    Failed,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for SiteProvisioningState {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for SiteProvisioningState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for SiteProvisioningState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::NotApplicable => serializer.serialize_unit_variant("SiteProvisioningState", 0u32, "NotApplicable"),
            Self::Adding => serializer.serialize_unit_variant("SiteProvisioningState", 1u32, "Adding"),
            Self::Updating => serializer.serialize_unit_variant("SiteProvisioningState", 2u32, "Updating"),
            Self::Deleting => serializer.serialize_unit_variant("SiteProvisioningState", 3u32, "Deleting"),
            Self::Provisioned => serializer.serialize_unit_variant("SiteProvisioningState", 4u32, "Provisioned"),
            Self::Failed => serializer.serialize_unit_variant("SiteProvisioningState", 5u32, "Failed"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Reference to a site resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SiteResourceId {
    #[doc = "Site resource ID."]
    pub id: String,
}
impl SiteResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "Network slice resource. Must be created in the same location as its parent mobile network."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Slice {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Network slice properties."]
    pub properties: SlicePropertiesFormat,
}
impl Slice {
    pub fn new(tracked_resource: TrackedResource, properties: SlicePropertiesFormat) -> Self {
        Self {
            tracked_resource,
            properties,
        }
    }
}
#[doc = "Per-slice settings"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SliceConfiguration {
    #[doc = "Reference to a slice resource."]
    pub slice: SliceResourceId,
    #[doc = "Reference to a data network resource."]
    #[serde(rename = "defaultDataNetwork")]
    pub default_data_network: DataNetworkResourceId,
    #[doc = "The allowed data networks and the settings to use for them. The list must not contain duplicate items and must contain at least one item."]
    #[serde(rename = "dataNetworkConfigurations")]
    pub data_network_configurations: Vec<DataNetworkConfiguration>,
}
impl SliceConfiguration {
    pub fn new(
        slice: SliceResourceId,
        default_data_network: DataNetworkResourceId,
        data_network_configurations: Vec<DataNetworkConfiguration>,
    ) -> Self {
        Self {
            slice,
            default_data_network,
            data_network_configurations,
        }
    }
}
#[doc = "Response for network slice API service call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SliceListResult {
    #[doc = "A list of network slices in a mobile network."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<Slice>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for SliceListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl SliceListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Network slice properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlicePropertiesFormat {
    #[doc = "The current provisioning state."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "Single-network slice selection assistance information (S-NSSAI)."]
    pub snssai: Snssai,
    #[doc = "An optional description for this network slice."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
impl SlicePropertiesFormat {
    pub fn new(snssai: Snssai) -> Self {
        Self {
            provisioning_state: None,
            snssai,
            description: None,
        }
    }
}
#[doc = "Reference to a slice resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SliceResourceId {
    #[doc = "Slice resource ID."]
    pub id: String,
}
impl SliceResourceId {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
#[doc = "Single-network slice selection assistance information (S-NSSAI)."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Snssai {
    #[doc = "Slice/service type (SST)."]
    pub sst: i32,
    #[doc = "Slice differentiator (SD)."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd: Option<String>,
}
impl Snssai {
    pub fn new(sst: i32) -> Self {
        Self { sst, sd: None }
    }
}
#[doc = "Reference to another sub resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubResource {
    #[doc = "Resource ID."]
    pub id: String,
}
impl SubResource {
    pub fn new(id: String) -> Self {
        Self { id }
    }
}
pub type Supi = String;
pub type Tac = String;
pub type TacRm = String;
#[doc = "Tags object for patch operations."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TagsObject {
    #[doc = "Resource tags."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl TagsObject {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The resource model definition for an Azure Resource Manager tracked top level resource which has 'tags' and a 'location'"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackedResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[doc = "Resource tags."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[doc = "The geo-location where the resource lives"]
    pub location: String,
}
impl TrackedResource {
    pub fn new(location: String) -> Self {
        Self {
            resource: Resource::default(),
            tags: None,
            location,
        }
    }
}
#[doc = "Traffic control permission."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "TrafficControlPermission")]
pub enum TrafficControlPermission {
    Enabled,
    Blocked,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for TrafficControlPermission {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for TrafficControlPermission {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for TrafficControlPermission {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Enabled => serializer.serialize_unit_variant("TrafficControlPermission", 0u32, "Enabled"),
            Self::Blocked => serializer.serialize_unit_variant("TrafficControlPermission", 1u32, "Blocked"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "UE Connection Info for 4G"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeConnectionInfo4G {
    #[doc = "UE Location Info properties"]
    #[serde(rename = "locationInfo", default, skip_serializing_if = "Option::is_none")]
    pub location_info: Option<UeLocationInfo>,
    #[doc = "Global RAN Node ID"]
    #[serde(rename = "globalRanNodeId")]
    pub global_ran_node_id: GlobalRanNodeId,
    #[doc = "Per-UE transport network layer association"]
    #[serde(rename = "perUeTnla", default, skip_serializing_if = "Option::is_none")]
    pub per_ue_tnla: Option<String>,
    #[doc = "MME S1AP identifier"]
    #[serde(rename = "mmeS1apId")]
    pub mme_s1ap_id: i64,
    #[doc = "eNodeB S1AP identifier"]
    #[serde(rename = "enbS1apId")]
    pub enb_s1ap_id: i64,
    #[doc = "Last Visited TAI"]
    #[serde(rename = "lastVisitedTai", default, skip_serializing_if = "Option::is_none")]
    pub last_visited_tai: Option<String>,
    #[doc = "State of the UE."]
    #[serde(rename = "ueState")]
    pub ue_state: UeState,
    #[doc = "Radio connection establishment cause"]
    #[serde(rename = "rrcEstablishmentCause")]
    pub rrc_establishment_cause: RrcEstablishmentCause,
    #[doc = "The UE's usage setting"]
    #[serde(rename = "ueUsageSetting", default, skip_serializing_if = "Option::is_none")]
    pub ue_usage_setting: Option<UeUsageSetting>,
    #[doc = "The timestamp of last activity of UE (UTC)."]
    #[serde(rename = "lastActivityTime", default, with = "azure_core::date::rfc3339::option")]
    pub last_activity_time: Option<::time::OffsetDateTime>,
}
impl UeConnectionInfo4G {
    pub fn new(
        global_ran_node_id: GlobalRanNodeId,
        mme_s1ap_id: i64,
        enb_s1ap_id: i64,
        ue_state: UeState,
        rrc_establishment_cause: RrcEstablishmentCause,
    ) -> Self {
        Self {
            location_info: None,
            global_ran_node_id,
            per_ue_tnla: None,
            mme_s1ap_id,
            enb_s1ap_id,
            last_visited_tai: None,
            ue_state,
            rrc_establishment_cause,
            ue_usage_setting: None,
            last_activity_time: None,
        }
    }
}
#[doc = "UE Connection Info for 5G."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeConnectionInfo5G {
    #[doc = "UE Location Info properties"]
    #[serde(rename = "locationInfo", default, skip_serializing_if = "Option::is_none")]
    pub location_info: Option<UeLocationInfo>,
    #[doc = "Global RAN Node ID"]
    #[serde(rename = "globalRanNodeId")]
    pub global_ran_node_id: GlobalRanNodeId,
    #[doc = "Per-UE transport network layer association"]
    #[serde(rename = "perUeTnla", default, skip_serializing_if = "Option::is_none")]
    pub per_ue_tnla: Option<String>,
    #[doc = "The AMF UE NGAP ID"]
    #[serde(rename = "amfUeNgapId")]
    pub amf_ue_ngap_id: i64,
    #[doc = "The RAN UE NGAP ID"]
    #[serde(rename = "ranUeNgapId")]
    pub ran_ue_ngap_id: i64,
    #[doc = "Last Visited TAI"]
    #[serde(rename = "lastVisitedTai", default, skip_serializing_if = "Option::is_none")]
    pub last_visited_tai: Option<String>,
    #[doc = "Allowed Network Slice Selection Assistance Information"]
    #[serde(
        rename = "allowedNssai",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_nssai: Vec<Snssai>,
    #[doc = "State of the UE."]
    #[serde(rename = "ueState")]
    pub ue_state: UeState,
    #[doc = "Radio connection establishment cause"]
    #[serde(rename = "rrcEstablishmentCause")]
    pub rrc_establishment_cause: RrcEstablishmentCause,
    #[doc = "The UE's usage setting"]
    #[serde(rename = "ueUsageSetting", default, skip_serializing_if = "Option::is_none")]
    pub ue_usage_setting: Option<UeUsageSetting>,
    #[doc = "The timestamp of last activity of UE (UTC)."]
    #[serde(rename = "lastActivityTime", default, with = "azure_core::date::rfc3339::option")]
    pub last_activity_time: Option<::time::OffsetDateTime>,
}
impl UeConnectionInfo5G {
    pub fn new(
        global_ran_node_id: GlobalRanNodeId,
        amf_ue_ngap_id: i64,
        ran_ue_ngap_id: i64,
        ue_state: UeState,
        rrc_establishment_cause: RrcEstablishmentCause,
    ) -> Self {
        Self {
            location_info: None,
            global_ran_node_id,
            per_ue_tnla: None,
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            last_visited_tai: None,
            allowed_nssai: Vec::new(),
            ue_state,
            rrc_establishment_cause,
            ue_usage_setting: None,
            last_activity_time: None,
        }
    }
}
#[doc = "Basic UE Information."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeInfo {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Basic UE Information Properties."]
    pub properties: UeInfoPropertiesFormat,
}
impl UeInfo {
    pub fn new(properties: UeInfoPropertiesFormat) -> Self {
        Self {
            proxy_resource: ProxyResource::default(),
            properties,
        }
    }
}
#[doc = "UE Information for 4G."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeInfo4G {
    #[serde(flatten)]
    pub extended_ue_info_properties: ExtendedUeInfoProperties,
    #[doc = "UE Information properties for 4G."]
    pub info: UeInfo4GProperties,
}
impl UeInfo4G {
    pub fn new(extended_ue_info_properties: ExtendedUeInfoProperties, info: UeInfo4GProperties) -> Self {
        Self {
            extended_ue_info_properties,
            info,
        }
    }
}
#[doc = "UE Information properties for 4G."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeInfo4GProperties {
    #[doc = "International mobile subscriber identifier"]
    pub imsi: String,
    #[doc = "International mobile equipment identity"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imei: Option<String>,
    #[doc = "International mobile equipment identity – software version"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imeisv: Option<String>,
    #[doc = "Globally Unique Temporary Identifier (4G)"]
    pub guti: Guti4G,
    #[doc = "UE Connection Info for 4G"]
    #[serde(rename = "connectionInfo", default, skip_serializing_if = "Option::is_none")]
    pub connection_info: Option<UeConnectionInfo4G>,
    #[serde(
        rename = "sessionInfo",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub session_info: Vec<UeSessionInfo4G>,
}
impl UeInfo4GProperties {
    pub fn new(imsi: String, guti: Guti4G) -> Self {
        Self {
            imsi,
            imei: None,
            imeisv: None,
            guti,
            connection_info: None,
            session_info: Vec::new(),
        }
    }
}
#[doc = "UE Information for 5G."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeInfo5G {
    #[serde(flatten)]
    pub extended_ue_info_properties: ExtendedUeInfoProperties,
    #[doc = "UE Information properties for 5G."]
    pub info: UeInfo5GProperties,
}
impl UeInfo5G {
    pub fn new(extended_ue_info_properties: ExtendedUeInfoProperties, info: UeInfo5GProperties) -> Self {
        Self {
            extended_ue_info_properties,
            info,
        }
    }
}
#[doc = "UE Information properties for 5G."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeInfo5GProperties {
    #[doc = "Subscription Permanent Identifier"]
    pub supi: Supi,
    #[doc = "Permanent Equipment Identifier"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pei: Option<Pei>,
    #[doc = "5G GUTI"]
    #[serde(rename = "fivegGuti")]
    pub fiveg_guti: Guti5G,
    #[doc = "UE Connection Info for 5G."]
    #[serde(rename = "connectionInfo", default, skip_serializing_if = "Option::is_none")]
    pub connection_info: Option<UeConnectionInfo5G>,
    #[serde(
        rename = "sessionInfo",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub session_info: Vec<UeSessionInfo5G>,
}
impl UeInfo5GProperties {
    pub fn new(supi: Supi, fiveg_guti: Guti5G) -> Self {
        Self {
            supi,
            pei: None,
            fiveg_guti,
            connection_info: None,
            session_info: Vec::new(),
        }
    }
}
#[doc = "Response for packet core list UEs API call."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct UeInfoList {
    #[doc = "A list of UEs in a packet core and their basic information."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<UeInfo>,
    #[doc = "The URL to get the next set of results."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for UeInfoList {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl UeInfoList {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Basic UE Information Properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeInfoPropertiesFormat {
    #[doc = "RAT Type"]
    #[serde(rename = "ratType")]
    pub rat_type: RatType,
    #[doc = "State of the UE."]
    #[serde(rename = "ueState")]
    pub ue_state: UeState,
    #[serde(
        rename = "ueIpAddresses",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ue_ip_addresses: Vec<DnnIpPair>,
    #[doc = "The timestamp of last list UEs call to the packet core (UTC)."]
    #[serde(rename = "lastReadAt", default, with = "azure_core::date::rfc3339::option")]
    pub last_read_at: Option<::time::OffsetDateTime>,
}
impl UeInfoPropertiesFormat {
    pub fn new(rat_type: RatType, ue_state: UeState) -> Self {
        Self {
            rat_type,
            ue_state,
            ue_ip_addresses: Vec::new(),
            last_read_at: None,
        }
    }
}
#[doc = "UE IP address"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct UeIpAddress {
    #[doc = "IPv4 address."]
    #[serde(rename = "ipV4Addr", default, skip_serializing_if = "Option::is_none")]
    pub ip_v4_addr: Option<Ipv4Addr>,
}
impl UeIpAddress {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "UE Location Info properties"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeLocationInfo {
    #[doc = "Location Type"]
    #[serde(rename = "locationType")]
    pub location_type: String,
    #[doc = "Tracking Area Code (TAC)."]
    pub tac: Tac,
    #[doc = "Public land mobile network (PLMN) ID. This is made up of the mobile country code and mobile network code, as defined in https://www.itu.int/rec/T-REC-E.212. The values 001-01 and 001-001 can be used for testing and the values 999-99 and 999-999 can be used on internal private networks."]
    pub plmn: PlmnId,
}
impl UeLocationInfo {
    pub fn new(location_type: String, tac: Tac, plmn: PlmnId) -> Self {
        Self { location_type, tac, plmn }
    }
}
#[doc = "QoS Flow"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeQosFlow {
    #[doc = "Qos Flow Identifier"]
    pub qfi: Qfi,
    #[doc = "5G QoS Identifier."]
    pub fiveqi: N5Qi,
    #[doc = "Aggregate maximum bit rate."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbr: Option<Ambr>,
    #[doc = "Aggregate maximum bit rate."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gbr: Option<Ambr>,
}
impl UeQosFlow {
    pub fn new(qfi: Qfi, fiveqi: N5Qi) -> Self {
        Self {
            qfi,
            fiveqi,
            mbr: None,
            gbr: None,
        }
    }
}
#[doc = "UE Session Info for 4G"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeSessionInfo4G {
    #[doc = "EPS bearer identifier"]
    pub ebi: i64,
    #[doc = "Access point name"]
    pub apn: String,
    #[doc = "UE IP address"]
    #[serde(rename = "ueIpAddress")]
    pub ue_ip_address: UeIpAddress,
    #[doc = "Packet Data Network Type"]
    #[serde(rename = "pdnType")]
    pub pdn_type: PdnType,
}
impl UeSessionInfo4G {
    pub fn new(ebi: i64, apn: String, ue_ip_address: UeIpAddress, pdn_type: PdnType) -> Self {
        Self {
            ebi,
            apn,
            ue_ip_address,
            pdn_type,
        }
    }
}
#[doc = "UE Session Info for 5G."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UeSessionInfo5G {
    #[doc = "PDU session identifier"]
    #[serde(rename = "pduSessionId")]
    pub pdu_session_id: PduSessionId,
    #[doc = "Data network name"]
    pub dnn: Dnn,
    #[doc = "Single-network slice selection assistance information (S-NSSAI)."]
    pub snssai: Snssai,
    #[doc = "UE IP address"]
    #[serde(rename = "ueIpAddress")]
    pub ue_ip_address: UeIpAddress,
    #[doc = "Packet Data Network Type"]
    #[serde(rename = "pdnType")]
    pub pdn_type: PdnType,
    #[doc = "Aggregate maximum bit rate."]
    pub ambr: Ambr,
    #[serde(rename = "qosFlow")]
    pub qos_flow: Vec<UeQosFlow>,
}
impl UeSessionInfo5G {
    pub fn new(
        pdu_session_id: PduSessionId,
        dnn: Dnn,
        snssai: Snssai,
        ue_ip_address: UeIpAddress,
        pdn_type: PdnType,
        ambr: Ambr,
        qos_flow: Vec<UeQosFlow>,
    ) -> Self {
        Self {
            pdu_session_id,
            dnn,
            snssai,
            ue_ip_address,
            pdn_type,
            ambr,
            qos_flow,
        }
    }
}
#[doc = "State of the UE."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "UeState")]
pub enum UeState {
    Connected,
    Idle,
    Detached,
    Deregistered,
    Unknown,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for UeState {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for UeState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for UeState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Connected => serializer.serialize_unit_variant("UeState", 0u32, "Connected"),
            Self::Idle => serializer.serialize_unit_variant("UeState", 1u32, "Idle"),
            Self::Detached => serializer.serialize_unit_variant("UeState", 2u32, "Detached"),
            Self::Deregistered => serializer.serialize_unit_variant("UeState", 3u32, "Deregistered"),
            Self::Unknown => serializer.serialize_unit_variant("UeState", 4u32, "Unknown"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "The UE's usage setting"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "UeUsageSetting")]
pub enum UeUsageSetting {
    VoiceCentric,
    DataCentric,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for UeUsageSetting {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for UeUsageSetting {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for UeUsageSetting {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::VoiceCentric => serializer.serialize_unit_variant("UeUsageSetting", 0u32, "VoiceCentric"),
            Self::DataCentric => serializer.serialize_unit_variant("UeUsageSetting", 1u32, "DataCentric"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "The set of user assigned identities associated with the resource. The userAssignedIdentities dictionary keys will be ARM resource ids in the form: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName}. The dictionary values can be empty objects ({}) in requests."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct UserAssignedIdentities {}
impl UserAssignedIdentities {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "User assigned identity properties"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct UserAssignedIdentity {
    #[doc = "The principal ID of the assigned identity."]
    #[serde(rename = "principalId", default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[doc = "The client ID of the assigned identity."]
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}
impl UserAssignedIdentity {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct UserConsentConfiguration {
    #[doc = "Allow Microsoft to access non-PII telemetry information from the packet core."]
    #[serde(rename = "allowSupportTelemetryAccess", default, skip_serializing_if = "Option::is_none")]
    pub allow_support_telemetry_access: Option<bool>,
}
impl UserConsentConfiguration {
    pub fn new() -> Self {
        Self::default()
    }
}
pub type UserPlaneDataRoutes = Vec<serde_json::Value>;
#[doc = "The state of this packet core control plane version."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "VersionState")]
pub enum VersionState {
    Unknown,
    Preview,
    Validating,
    ValidationFailed,
    Active,
    Deprecated,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for VersionState {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for VersionState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for VersionState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Unknown => serializer.serialize_unit_variant("VersionState", 0u32, "Unknown"),
            Self::Preview => serializer.serialize_unit_variant("VersionState", 1u32, "Preview"),
            Self::Validating => serializer.serialize_unit_variant("VersionState", 2u32, "Validating"),
            Self::ValidationFailed => serializer.serialize_unit_variant("VersionState", 3u32, "ValidationFailed"),
            Self::Active => serializer.serialize_unit_variant("VersionState", 4u32, "Active"),
            Self::Deprecated => serializer.serialize_unit_variant("VersionState", 5u32, "Deprecated"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HomeNetworkPrivateKeysProvisioning {
    #[doc = "The provisioning state of the private keys for SUPI concealment."]
    pub state: home_network_private_keys_provisioning::State,
}
impl HomeNetworkPrivateKeysProvisioning {
    pub fn new(state: home_network_private_keys_provisioning::State) -> Self {
        Self { state }
    }
}
pub mod home_network_private_keys_provisioning {
    use super::*;
    #[doc = "The provisioning state of the private keys for SUPI concealment."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "State")]
    pub enum State {
        NotProvisioned,
        Provisioned,
        Failed,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for State {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for State {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for State {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::NotProvisioned => serializer.serialize_unit_variant("State", 0u32, "NotProvisioned"),
                Self::Provisioned => serializer.serialize_unit_variant("State", 1u32, "Provisioned"),
                Self::Failed => serializer.serialize_unit_variant("State", 2u32, "Failed"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
}
#[doc = "A key used for SUPI concealment."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HomeNetworkPublicKey {
    #[doc = "The Home Network Public Key Identifier determines which public key was used to generate the SUCI sent to the AMF. See TS 23.003 Section 2.2B Section 5."]
    pub id: i32,
    #[doc = "The URL of Azure Key Vault secret containing the private key, versioned or unversioned. For example: https://contosovault.vault.azure.net/secrets/mySuciPrivateKey/562a4bb76b524a1493a6afe8e536ee78."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}
impl HomeNetworkPublicKey {
    pub fn new(id: i32) -> Self {
        Self { id, url: None }
    }
}
pub type HomeNetworkPublicKeys = Vec<HomeNetworkPublicKey>;
#[doc = "Configuration relating to a particular PLMN"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicLandMobileNetwork {
    #[serde(flatten)]
    pub plmn_id: PlmnId,
    #[doc = "Configuration relating to SUPI concealment."]
    #[serde(rename = "homeNetworkPublicKeys", default, skip_serializing_if = "Option::is_none")]
    pub home_network_public_keys: Option<public_land_mobile_network::HomeNetworkPublicKeys>,
}
impl PublicLandMobileNetwork {
    pub fn new(plmn_id: PlmnId) -> Self {
        Self {
            plmn_id,
            home_network_public_keys: None,
        }
    }
}
pub mod public_land_mobile_network {
    use super::*;
    #[doc = "Configuration relating to SUPI concealment."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
    pub struct HomeNetworkPublicKeys {
        #[serde(rename = "profileA", default, skip_serializing_if = "Option::is_none")]
        pub profile_a: Option<Box<HomeNetworkPublicKeys>>,
        #[serde(rename = "profileB", default, skip_serializing_if = "Option::is_none")]
        pub profile_b: Option<Box<HomeNetworkPublicKeys>>,
    }
    impl HomeNetworkPublicKeys {
        pub fn new() -> Self {
            Self::default()
        }
    }
}
#[doc = "Metadata pertaining to creation and last modification of the resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SystemData {
    #[doc = "The identity that created the resource."]
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[doc = "The type of identity that created the resource."]
    #[serde(rename = "createdByType", default, skip_serializing_if = "Option::is_none")]
    pub created_by_type: Option<system_data::CreatedByType>,
    #[doc = "The timestamp of resource creation (UTC)."]
    #[serde(rename = "createdAt", default, with = "azure_core::date::rfc3339::option")]
    pub created_at: Option<::time::OffsetDateTime>,
    #[doc = "The identity that last modified the resource."]
    #[serde(rename = "lastModifiedBy", default, skip_serializing_if = "Option::is_none")]
    pub last_modified_by: Option<String>,
    #[doc = "The type of identity that last modified the resource."]
    #[serde(rename = "lastModifiedByType", default, skip_serializing_if = "Option::is_none")]
    pub last_modified_by_type: Option<system_data::LastModifiedByType>,
    #[doc = "The timestamp of resource last modification (UTC)"]
    #[serde(rename = "lastModifiedAt", default, with = "azure_core::date::rfc3339::option")]
    pub last_modified_at: Option<::time::OffsetDateTime>,
}
impl SystemData {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod system_data {
    use super::*;
    #[doc = "The type of identity that created the resource."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "CreatedByType")]
    pub enum CreatedByType {
        User,
        Application,
        ManagedIdentity,
        Key,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for CreatedByType {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for CreatedByType {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for CreatedByType {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::User => serializer.serialize_unit_variant("CreatedByType", 0u32, "User"),
                Self::Application => serializer.serialize_unit_variant("CreatedByType", 1u32, "Application"),
                Self::ManagedIdentity => serializer.serialize_unit_variant("CreatedByType", 2u32, "ManagedIdentity"),
                Self::Key => serializer.serialize_unit_variant("CreatedByType", 3u32, "Key"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
    #[doc = "The type of identity that last modified the resource."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "LastModifiedByType")]
    pub enum LastModifiedByType {
        User,
        Application,
        ManagedIdentity,
        Key,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for LastModifiedByType {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for LastModifiedByType {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for LastModifiedByType {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::User => serializer.serialize_unit_variant("LastModifiedByType", 0u32, "User"),
                Self::Application => serializer.serialize_unit_variant("LastModifiedByType", 1u32, "Application"),
                Self::ManagedIdentity => serializer.serialize_unit_variant("LastModifiedByType", 2u32, "ManagedIdentity"),
                Self::Key => serializer.serialize_unit_variant("LastModifiedByType", 3u32, "Key"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
}
