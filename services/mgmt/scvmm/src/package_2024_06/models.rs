#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::de::{value, Deserializer, IntoDeserializer};
use serde::{Deserialize, Serialize, Serializer};
use std::str::FromStr;
#[doc = "Network address allocation method."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "AllocationMethod")]
pub enum AllocationMethod {
    Dynamic,
    Static,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for AllocationMethod {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for AllocationMethod {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for AllocationMethod {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Dynamic => serializer.serialize_unit_variant("AllocationMethod", 0u32, "Dynamic"),
            Self::Static => serializer.serialize_unit_variant("AllocationMethod", 1u32, "Static"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "The AvailabilitySets resource definition."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AvailabilitySet {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<AvailabilitySetProperties>,
    #[doc = "The extended location."]
    #[serde(rename = "extendedLocation")]
    pub extended_location: ExtendedLocation,
}
impl AvailabilitySet {
    pub fn new(tracked_resource: TrackedResource, extended_location: ExtendedLocation) -> Self {
        Self {
            tracked_resource,
            properties: None,
            extended_location,
        }
    }
}
#[doc = "Availability Set model"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AvailabilitySetListItem {
    #[doc = "Gets the ARM Id of the microsoft.scvmm/availabilitySets resource."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[doc = "Gets or sets the name of the availability set."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
impl AvailabilitySetListItem {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The response of a AvailabilitySet list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AvailabilitySetListResult {
    #[doc = "The AvailabilitySet items on this page"]
    pub value: Vec<AvailabilitySet>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for AvailabilitySetListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl AvailabilitySetListResult {
    pub fn new(value: Vec<AvailabilitySet>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AvailabilitySetProperties {
    #[doc = "Name of the availability set."]
    #[serde(rename = "availabilitySetName", default, skip_serializing_if = "Option::is_none")]
    pub availability_set_name: Option<String>,
    #[doc = "ARM Id of the vmmServer resource in which this resource resides."]
    #[serde(rename = "vmmServerId", default, skip_serializing_if = "Option::is_none")]
    pub vmm_server_id: Option<String>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
}
impl AvailabilitySetProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The type used for updating tags in AvailabilitySet resources."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AvailabilitySetTagsUpdate {
    #[doc = "Resource tags."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl AvailabilitySetTagsUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Checkpoint {
    #[doc = "Gets ID of parent of the checkpoint."]
    #[serde(rename = "parentCheckpointID", default, skip_serializing_if = "Option::is_none")]
    pub parent_checkpoint_id: Option<String>,
    #[doc = "Gets ID of the checkpoint."]
    #[serde(rename = "checkpointID", default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    #[doc = "Gets name of the checkpoint."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Gets description of the checkpoint."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
impl Checkpoint {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The Clouds resource definition."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cloud {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<CloudProperties>,
    #[doc = "The extended location."]
    #[serde(rename = "extendedLocation")]
    pub extended_location: ExtendedLocation,
}
impl Cloud {
    pub fn new(tracked_resource: TrackedResource, extended_location: ExtendedLocation) -> Self {
        Self {
            tracked_resource,
            properties: None,
            extended_location,
        }
    }
}
#[doc = "Cloud Capacity model"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CloudCapacity {
    #[doc = "CPUCount specifies the maximum number of CPUs that can be allocated in the cloud."]
    #[serde(rename = "cpuCount", default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i64>,
    #[doc = "MemoryMB specifies a memory usage limit in megabytes."]
    #[serde(rename = "memoryMB", default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<i64>,
    #[doc = "VMCount gives the max number of VMs that can be deployed in the cloud."]
    #[serde(rename = "vmCount", default, skip_serializing_if = "Option::is_none")]
    pub vm_count: Option<i64>,
}
impl CloudCapacity {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The Cloud inventory item."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CloudInventoryItem {
    #[serde(flatten)]
    pub inventory_item_properties: InventoryItemProperties,
}
impl CloudInventoryItem {
    pub fn new(inventory_item_properties: InventoryItemProperties) -> Self {
        Self { inventory_item_properties }
    }
}
#[doc = "The response of a Cloud list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CloudListResult {
    #[doc = "The Cloud items on this page"]
    pub value: Vec<Cloud>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for CloudListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl CloudListResult {
    pub fn new(value: Vec<Cloud>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CloudProperties {
    #[doc = "Gets or sets the inventory Item ID for the resource."]
    #[serde(rename = "inventoryItemId", default, skip_serializing_if = "Option::is_none")]
    pub inventory_item_id: Option<String>,
    #[doc = "Unique ID of the cloud."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[doc = "ARM Id of the vmmServer resource in which this resource resides."]
    #[serde(rename = "vmmServerId", default, skip_serializing_if = "Option::is_none")]
    pub vmm_server_id: Option<String>,
    #[doc = "Name of the cloud in VmmServer."]
    #[serde(rename = "cloudName", default, skip_serializing_if = "Option::is_none")]
    pub cloud_name: Option<String>,
    #[doc = "Cloud Capacity model"]
    #[serde(rename = "cloudCapacity", default, skip_serializing_if = "Option::is_none")]
    pub cloud_capacity: Option<CloudCapacity>,
    #[doc = "List of QoS policies available for the cloud."]
    #[serde(
        rename = "storageQoSPolicies",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub storage_qo_s_policies: Vec<StorageQosPolicy>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
}
impl CloudProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The type used for updating tags in Cloud resources."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CloudTagsUpdate {
    #[doc = "Resource tags."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl CloudTagsUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Create diff disk."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "CreateDiffDisk")]
pub enum CreateDiffDisk {
    #[serde(rename = "true")]
    True,
    #[serde(rename = "false")]
    False,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for CreateDiffDisk {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for CreateDiffDisk {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for CreateDiffDisk {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::True => serializer.serialize_unit_variant("CreateDiffDisk", 0u32, "true"),
            Self::False => serializer.serialize_unit_variant("CreateDiffDisk", 1u32, "false"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Dynamic memory enabled."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "DynamicMemoryEnabled")]
pub enum DynamicMemoryEnabled {
    #[serde(rename = "true")]
    True,
    #[serde(rename = "false")]
    False,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for DynamicMemoryEnabled {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for DynamicMemoryEnabled {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for DynamicMemoryEnabled {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::True => serializer.serialize_unit_variant("DynamicMemoryEnabled", 0u32, "true"),
            Self::False => serializer.serialize_unit_variant("DynamicMemoryEnabled", 1u32, "false"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
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
#[doc = "The extended location."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ExtendedLocation {
    #[doc = "The extended location type."]
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[doc = "The extended location name."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
impl ExtendedLocation {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the GuestAgent."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct GuestAgent {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<GuestAgentProperties>,
}
impl GuestAgent {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The response of a GuestAgent list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GuestAgentListResult {
    #[doc = "The GuestAgent items on this page"]
    pub value: Vec<GuestAgent>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for GuestAgentListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl GuestAgentListResult {
    pub fn new(value: Vec<GuestAgent>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct GuestAgentProperties {
    #[doc = "Gets a unique identifier for this resource."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[doc = "Username / Password Credentials to connect to guest."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<GuestCredential>,
    #[doc = "HTTP Proxy configuration for the VM."]
    #[serde(rename = "httpProxyConfig", default, skip_serializing_if = "Option::is_none")]
    pub http_proxy_config: Option<HttpProxyConfiguration>,
    #[doc = "Guest agent provisioning action."]
    #[serde(rename = "provisioningAction", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_action: Option<ProvisioningAction>,
    #[doc = "Gets the guest agent status."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[doc = "Gets the name of the corresponding resource in Kubernetes."]
    #[serde(rename = "customResourceName", default, skip_serializing_if = "Option::is_none")]
    pub custom_resource_name: Option<String>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[doc = "The resource id of the private link scope this machine is assigned to, if any."]
    #[serde(rename = "privateLinkScopeResourceId", default, skip_serializing_if = "Option::is_none")]
    pub private_link_scope_resource_id: Option<String>,
}
impl GuestAgentProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Username / Password Credentials to connect to guest."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GuestCredential {
    #[doc = "Gets or sets username to connect with the guest."]
    pub username: String,
    #[doc = "Gets or sets the password to connect with the guest."]
    pub password: String,
}
impl GuestCredential {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct HardwareProfile {
    #[doc = "MemoryMB is the size of a virtual machine's memory, in MB."]
    #[serde(rename = "memoryMB", default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<i32>,
    #[doc = "Gets or sets the number of vCPUs for the vm."]
    #[serde(rename = "cpuCount", default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i32>,
    #[doc = "Limit CPU for migration."]
    #[serde(rename = "limitCpuForMigration", default, skip_serializing_if = "Option::is_none")]
    pub limit_cpu_for_migration: Option<LimitCpuForMigration>,
    #[doc = "Dynamic memory enabled."]
    #[serde(rename = "dynamicMemoryEnabled", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_enabled: Option<DynamicMemoryEnabled>,
    #[doc = "Gets or sets the max dynamic memory for the vm."]
    #[serde(rename = "dynamicMemoryMaxMB", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_max_mb: Option<i32>,
    #[doc = "Gets or sets the min dynamic memory for the vm."]
    #[serde(rename = "dynamicMemoryMinMB", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_min_mb: Option<i32>,
    #[doc = "Highly available."]
    #[serde(rename = "isHighlyAvailable", default, skip_serializing_if = "Option::is_none")]
    pub is_highly_available: Option<IsHighlyAvailable>,
}
impl HardwareProfile {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the resource update properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct HardwareProfileUpdate {
    #[doc = "MemoryMB is the size of a virtual machine's memory, in MB."]
    #[serde(rename = "memoryMB", default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<i32>,
    #[doc = "Gets or sets the number of vCPUs for the vm."]
    #[serde(rename = "cpuCount", default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i32>,
    #[doc = "Limit CPU for migration."]
    #[serde(rename = "limitCpuForMigration", default, skip_serializing_if = "Option::is_none")]
    pub limit_cpu_for_migration: Option<LimitCpuForMigration>,
    #[doc = "Dynamic memory enabled."]
    #[serde(rename = "dynamicMemoryEnabled", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_enabled: Option<DynamicMemoryEnabled>,
    #[doc = "Gets or sets the max dynamic memory for the vm."]
    #[serde(rename = "dynamicMemoryMaxMB", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_max_mb: Option<i32>,
    #[doc = "Gets or sets the min dynamic memory for the vm."]
    #[serde(rename = "dynamicMemoryMinMB", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_min_mb: Option<i32>,
}
impl HardwareProfileUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "HTTP Proxy configuration for the VM."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct HttpProxyConfiguration {
    #[doc = "Gets or sets httpsProxy url."]
    #[serde(rename = "httpsProxy", default, skip_serializing_if = "Option::is_none")]
    pub https_proxy: Option<String>,
}
impl HttpProxyConfiguration {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Specifies the vmmServer infrastructure specific settings for the virtual machine instance."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InfrastructureProfile {
    #[doc = "Gets or sets the inventory Item ID for the resource."]
    #[serde(rename = "inventoryItemId", default, skip_serializing_if = "Option::is_none")]
    pub inventory_item_id: Option<String>,
    #[doc = "ARM Id of the vmmServer resource in which this resource resides."]
    #[serde(rename = "vmmServerId", default, skip_serializing_if = "Option::is_none")]
    pub vmm_server_id: Option<String>,
    #[doc = "ARM Id of the cloud resource to use for deploying the vm."]
    #[serde(rename = "cloudId", default, skip_serializing_if = "Option::is_none")]
    pub cloud_id: Option<String>,
    #[doc = "ARM Id of the template resource to use for deploying the vm."]
    #[serde(rename = "templateId", default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[doc = "VMName is the name of VM on the SCVmm server."]
    #[serde(rename = "vmName", default, skip_serializing_if = "Option::is_none")]
    pub vm_name: Option<String>,
    #[doc = "Unique ID of the virtual machine."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[doc = "Defines the resource properties."]
    #[serde(rename = "lastRestoredVMCheckpoint", default, skip_serializing_if = "Option::is_none")]
    pub last_restored_vm_checkpoint: Option<Checkpoint>,
    #[doc = "Checkpoints in the vm."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub checkpoints: Vec<Checkpoint>,
    #[doc = "Type of checkpoint supported for the vm."]
    #[serde(rename = "checkpointType", default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_type: Option<String>,
    #[doc = "Gets or sets the generation for the vm."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i32>,
    #[doc = "Gets or sets the bios guid for the vm."]
    #[serde(rename = "biosGuid", default, skip_serializing_if = "Option::is_none")]
    pub bios_guid: Option<String>,
}
impl InfrastructureProfile {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Specifies the vmmServer infrastructure specific update settings for the virtual machine instance."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InfrastructureProfileUpdate {
    #[doc = "Type of checkpoint supported for the vm."]
    #[serde(rename = "checkpointType", default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_type: Option<String>,
}
impl InfrastructureProfileUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the inventory item."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InventoryItem {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<InventoryItemPropertiesUnion>,
    #[doc = "Metadata used by portal/tooling/etc to render different UX experiences for resources of the same type; e.g. ApiApps are a kind of Microsoft.Web/sites type.  If supported, the resource provider must validate and persist this value."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}
impl InventoryItem {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InventoryItemDetails {
    #[doc = "Gets or sets the inventory Item ID for the resource."]
    #[serde(rename = "inventoryItemId", default, skip_serializing_if = "Option::is_none")]
    pub inventory_item_id: Option<String>,
    #[doc = "Gets or sets the Managed Object name in Vmm for the resource."]
    #[serde(rename = "inventoryItemName", default, skip_serializing_if = "Option::is_none")]
    pub inventory_item_name: Option<String>,
}
impl InventoryItemDetails {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The response of a InventoryItem list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InventoryItemListResult {
    #[doc = "The InventoryItem items on this page"]
    pub value: Vec<InventoryItem>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for InventoryItemListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl InventoryItemListResult {
    pub fn new(value: Vec<InventoryItem>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InventoryItemProperties {
    #[doc = "Gets the tracked resource id corresponding to the inventory resource."]
    #[serde(rename = "managedResourceId", default, skip_serializing_if = "Option::is_none")]
    pub managed_resource_id: Option<String>,
    #[doc = "Gets the UUID (which is assigned by Vmm) for the inventory item."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[doc = "Gets the Managed Object name in Vmm for the inventory item."]
    #[serde(rename = "inventoryItemName", default, skip_serializing_if = "Option::is_none")]
    pub inventory_item_name: Option<String>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
}
impl InventoryItemProperties {
    pub fn new() -> Self {
        Self {
            managed_resource_id: None,
            uuid: None,
            inventory_item_name: None,
            provisioning_state: None,
        }
    }
}
#[doc = "The inventory type"]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "inventoryType")]
pub enum InventoryItemPropertiesUnion {
    Cloud(CloudInventoryItem),
    VirtualMachine(VirtualMachineInventoryItem),
    VirtualMachineTemplate(VirtualMachineTemplateInventoryItem),
    VirtualNetwork(VirtualNetworkInventoryItem),
}
#[doc = "The inventory type"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "InventoryType")]
pub enum InventoryType {
    Cloud,
    VirtualNetwork,
    VirtualMachine,
    VirtualMachineTemplate,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for InventoryType {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for InventoryType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for InventoryType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Cloud => serializer.serialize_unit_variant("InventoryType", 0u32, "Cloud"),
            Self::VirtualNetwork => serializer.serialize_unit_variant("InventoryType", 1u32, "VirtualNetwork"),
            Self::VirtualMachine => serializer.serialize_unit_variant("InventoryType", 2u32, "VirtualMachine"),
            Self::VirtualMachineTemplate => serializer.serialize_unit_variant("InventoryType", 3u32, "VirtualMachineTemplate"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Customizable."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "IsCustomizable")]
pub enum IsCustomizable {
    #[serde(rename = "true")]
    True,
    #[serde(rename = "false")]
    False,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for IsCustomizable {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for IsCustomizable {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for IsCustomizable {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::True => serializer.serialize_unit_variant("IsCustomizable", 0u32, "true"),
            Self::False => serializer.serialize_unit_variant("IsCustomizable", 1u32, "false"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Highly available."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "IsHighlyAvailable")]
pub enum IsHighlyAvailable {
    #[serde(rename = "true")]
    True,
    #[serde(rename = "false")]
    False,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for IsHighlyAvailable {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for IsHighlyAvailable {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for IsHighlyAvailable {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::True => serializer.serialize_unit_variant("IsHighlyAvailable", 0u32, "true"),
            Self::False => serializer.serialize_unit_variant("IsHighlyAvailable", 1u32, "false"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Limit CPU for migration."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "LimitCpuForMigration")]
pub enum LimitCpuForMigration {
    #[serde(rename = "true")]
    True,
    #[serde(rename = "false")]
    False,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for LimitCpuForMigration {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for LimitCpuForMigration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for LimitCpuForMigration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::True => serializer.serialize_unit_variant("LimitCpuForMigration", 0u32, "true"),
            Self::False => serializer.serialize_unit_variant("LimitCpuForMigration", 1u32, "false"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Network Interface model"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NetworkInterface {
    #[doc = "Gets or sets the name of the network interface."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Gets the display name of the network interface as shown in the vmmServer. This is the fallback label for a NIC when the name is not set."]
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[doc = "Gets the nic ipv4 addresses."]
    #[serde(
        rename = "ipv4Addresses",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ipv4_addresses: Vec<String>,
    #[doc = "Gets the nic ipv6 addresses."]
    #[serde(
        rename = "ipv6Addresses",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ipv6_addresses: Vec<String>,
    #[doc = "Gets or sets the nic MAC address."]
    #[serde(rename = "macAddress", default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[doc = "Gets or sets the ARM Id of the Microsoft.ScVmm/virtualNetwork resource to connect the nic."]
    #[serde(rename = "virtualNetworkId", default, skip_serializing_if = "Option::is_none")]
    pub virtual_network_id: Option<String>,
    #[doc = "Gets the name of the virtual network in vmmServer that the nic is connected to."]
    #[serde(rename = "networkName", default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    #[doc = "Network address allocation method."]
    #[serde(rename = "ipv4AddressType", default, skip_serializing_if = "Option::is_none")]
    pub ipv4_address_type: Option<AllocationMethod>,
    #[doc = "Network address allocation method."]
    #[serde(rename = "ipv6AddressType", default, skip_serializing_if = "Option::is_none")]
    pub ipv6_address_type: Option<AllocationMethod>,
    #[doc = "Network address allocation method."]
    #[serde(rename = "macAddressType", default, skip_serializing_if = "Option::is_none")]
    pub mac_address_type: Option<AllocationMethod>,
    #[doc = "Gets or sets the nic id."]
    #[serde(rename = "nicId", default, skip_serializing_if = "Option::is_none")]
    pub nic_id: Option<String>,
}
impl NetworkInterface {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Network Interface Update model"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NetworkInterfaceUpdate {
    #[doc = "Gets or sets the name of the network interface."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Gets or sets the nic MAC address."]
    #[serde(rename = "macAddress", default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[doc = "Gets or sets the ARM Id of the Microsoft.ScVmm/virtualNetwork resource to connect the nic."]
    #[serde(rename = "virtualNetworkId", default, skip_serializing_if = "Option::is_none")]
    pub virtual_network_id: Option<String>,
    #[doc = "Network address allocation method."]
    #[serde(rename = "ipv4AddressType", default, skip_serializing_if = "Option::is_none")]
    pub ipv4_address_type: Option<AllocationMethod>,
    #[doc = "Network address allocation method."]
    #[serde(rename = "ipv6AddressType", default, skip_serializing_if = "Option::is_none")]
    pub ipv6_address_type: Option<AllocationMethod>,
    #[doc = "Network address allocation method."]
    #[serde(rename = "macAddressType", default, skip_serializing_if = "Option::is_none")]
    pub mac_address_type: Option<AllocationMethod>,
    #[doc = "Gets or sets the nic id."]
    #[serde(rename = "nicId", default, skip_serializing_if = "Option::is_none")]
    pub nic_id: Option<String>,
}
impl NetworkInterfaceUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NetworkProfile {
    #[doc = "Gets or sets the list of network interfaces associated with the virtual machine."]
    #[serde(
        rename = "networkInterfaces",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_interfaces: Vec<NetworkInterface>,
}
impl NetworkProfile {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the resource update properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NetworkProfileUpdate {
    #[doc = "Gets or sets the list of network interfaces associated with the virtual machine."]
    #[serde(
        rename = "networkInterfaces",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_interfaces: Vec<NetworkInterfaceUpdate>,
}
impl NetworkProfileUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Details of a REST API operation, returned from the Resource Provider Operations API"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Operation {
    #[doc = "The name of the operation, as per Resource-Based Access Control (RBAC). Examples: \"Microsoft.Compute/virtualMachines/write\", \"Microsoft.Compute/virtualMachines/capture/action\""]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Whether the operation applies to data-plane. This is \"true\" for data-plane operations and \"false\" for ARM/control-plane operations."]
    #[serde(rename = "isDataAction", default, skip_serializing_if = "Option::is_none")]
    pub is_data_action: Option<bool>,
    #[doc = "Localized display information for this particular operation."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<operation::Display>,
    #[doc = "The intended executor of the operation; as in Resource Based Access Control (RBAC) and audit logs UX. Default value is \"user,system\""]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<operation::Origin>,
    #[doc = "Enum. Indicates the action type. \"Internal\" refers to actions that are for internal only APIs."]
    #[serde(rename = "actionType", default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<operation::ActionType>,
}
impl Operation {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod operation {
    use super::*;
    #[doc = "Localized display information for this particular operation."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
    pub struct Display {
        #[doc = "The localized friendly form of the resource provider name, e.g. \"Microsoft Monitoring Insights\" or \"Microsoft Compute\"."]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[doc = "The localized friendly name of the resource type related to this operation. E.g. \"Virtual Machines\" or \"Job Schedule Collections\"."]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[doc = "The concise, localized friendly name for the operation; suitable for dropdowns. E.g. \"Create or Update Virtual Machine\", \"Restart Virtual Machine\"."]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operation: Option<String>,
        #[doc = "The short, localized friendly description of the operation; suitable for tool tips and detailed views."]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }
    impl Display {
        pub fn new() -> Self {
            Self::default()
        }
    }
    #[doc = "The intended executor of the operation; as in Resource Based Access Control (RBAC) and audit logs UX. Default value is \"user,system\""]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "Origin")]
    pub enum Origin {
        #[serde(rename = "user")]
        User,
        #[serde(rename = "system")]
        System,
        #[serde(rename = "user,system")]
        UserSystem,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for Origin {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for Origin {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for Origin {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::User => serializer.serialize_unit_variant("Origin", 0u32, "user"),
                Self::System => serializer.serialize_unit_variant("Origin", 1u32, "system"),
                Self::UserSystem => serializer.serialize_unit_variant("Origin", 2u32, "user,system"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
    #[doc = "Enum. Indicates the action type. \"Internal\" refers to actions that are for internal only APIs."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "ActionType")]
    pub enum ActionType {
        Internal,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for ActionType {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for ActionType {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for ActionType {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::Internal => serializer.serialize_unit_variant("ActionType", 0u32, "Internal"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
}
#[doc = "A list of REST API operations supported by an Azure Resource Provider. It contains an URL link to get the next set of results."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct OperationListResult {
    #[doc = "List of operations supported by the resource provider"]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub value: Vec<Operation>,
    #[doc = "URL to get the next set of operation list results (if there are any)."]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for OperationListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl OperationListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct OsProfileForVmInstance {
    #[doc = "Admin password of the virtual machine."]
    #[serde(rename = "adminPassword", default, skip_serializing_if = "Option::is_none")]
    pub admin_password: Option<String>,
    #[doc = "Gets or sets computer name."]
    #[serde(rename = "computerName", default, skip_serializing_if = "Option::is_none")]
    pub computer_name: Option<String>,
    #[doc = "Virtual machine operating system type."]
    #[serde(rename = "osType", default, skip_serializing_if = "Option::is_none")]
    pub os_type: Option<OsType>,
    #[doc = "Gets os sku."]
    #[serde(rename = "osSku", default, skip_serializing_if = "Option::is_none")]
    pub os_sku: Option<String>,
    #[doc = "Gets os version."]
    #[serde(rename = "osVersion", default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[doc = "Gets or sets the domain name."]
    #[serde(rename = "domainName", default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[doc = "Gets or sets the domain username."]
    #[serde(rename = "domainUsername", default, skip_serializing_if = "Option::is_none")]
    pub domain_username: Option<String>,
    #[doc = "Password of the domain the VM has to join."]
    #[serde(rename = "domainPassword", default, skip_serializing_if = "Option::is_none")]
    pub domain_password: Option<String>,
    #[doc = "Gets or sets the workgroup."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workgroup: Option<String>,
    #[doc = "Gets or sets the product key.Input format xxxxx-xxxxx-xxxxx-xxxxx-xxxxx"]
    #[serde(rename = "productKey", default, skip_serializing_if = "Option::is_none")]
    pub product_key: Option<String>,
    #[doc = "Gets or sets the index value of the timezone."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<i32>,
    #[doc = "Get or sets the commands to be run once at the time of creation separated by semicolons."]
    #[serde(rename = "runOnceCommands", default, skip_serializing_if = "Option::is_none")]
    pub run_once_commands: Option<String>,
}
impl OsProfileForVmInstance {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Virtual machine operating system type."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "OsType")]
pub enum OsType {
    Windows,
    Linux,
    Other,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for OsType {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for OsType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for OsType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Windows => serializer.serialize_unit_variant("OsType", 0u32, "Windows"),
            Self::Linux => serializer.serialize_unit_variant("OsType", 1u32, "Linux"),
            Self::Other => serializer.serialize_unit_variant("OsType", 2u32, "Other"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "Guest agent provisioning action."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ProvisioningAction")]
pub enum ProvisioningAction {
    #[serde(rename = "install")]
    Install,
    #[serde(rename = "uninstall")]
    Uninstall,
    #[serde(rename = "repair")]
    Repair,
    #[serde(skip_deserializing)]
    UnknownValue(String),
}
impl FromStr for ProvisioningAction {
    type Err = value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::deserialize(s.into_deserializer())
    }
}
impl<'de> Deserialize<'de> for ProvisioningAction {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
        Ok(deserialized)
    }
}
impl Serialize for ProvisioningAction {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Install => serializer.serialize_unit_variant("ProvisioningAction", 0u32, "install"),
            Self::Uninstall => serializer.serialize_unit_variant("ProvisioningAction", 1u32, "uninstall"),
            Self::Repair => serializer.serialize_unit_variant("ProvisioningAction", 2u32, "repair"),
            Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
        }
    }
}
#[doc = "The provisioning state of the resource."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ProvisioningState")]
pub enum ProvisioningState {
    Succeeded,
    Failed,
    Canceled,
    Provisioning,
    Updating,
    Deleting,
    Accepted,
    Created,
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
            Self::Succeeded => serializer.serialize_unit_variant("ProvisioningState", 0u32, "Succeeded"),
            Self::Failed => serializer.serialize_unit_variant("ProvisioningState", 1u32, "Failed"),
            Self::Canceled => serializer.serialize_unit_variant("ProvisioningState", 2u32, "Canceled"),
            Self::Provisioning => serializer.serialize_unit_variant("ProvisioningState", 3u32, "Provisioning"),
            Self::Updating => serializer.serialize_unit_variant("ProvisioningState", 4u32, "Updating"),
            Self::Deleting => serializer.serialize_unit_variant("ProvisioningState", 5u32, "Deleting"),
            Self::Accepted => serializer.serialize_unit_variant("ProvisioningState", 6u32, "Accepted"),
            Self::Created => serializer.serialize_unit_variant("ProvisioningState", 7u32, "Created"),
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
#[doc = "Defines the stop action properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct StopVirtualMachineOptions {
    #[doc = "Gets or sets a value indicating whether to request non-graceful VM shutdown. True value for this flag indicates non-graceful shutdown whereas false indicates otherwise. Defaults to false."]
    #[serde(rename = "skipShutdown", default, skip_serializing_if = "Option::is_none")]
    pub skip_shutdown: Option<stop_virtual_machine_options::SkipShutdown>,
}
impl StopVirtualMachineOptions {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod stop_virtual_machine_options {
    use super::*;
    #[doc = "Gets or sets a value indicating whether to request non-graceful VM shutdown. True value for this flag indicates non-graceful shutdown whereas false indicates otherwise. Defaults to false."]
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(remote = "SkipShutdown")]
    pub enum SkipShutdown {
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(skip_deserializing)]
        UnknownValue(String),
    }
    impl FromStr for SkipShutdown {
        type Err = value::Error;
        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Self::deserialize(s.into_deserializer())
        }
    }
    impl<'de> Deserialize<'de> for SkipShutdown {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let deserialized = Self::from_str(&s).unwrap_or(Self::UnknownValue(s));
            Ok(deserialized)
        }
    }
    impl Serialize for SkipShutdown {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::True => serializer.serialize_unit_variant("SkipShutdown", 0u32, "true"),
                Self::False => serializer.serialize_unit_variant("SkipShutdown", 1u32, "false"),
                Self::UnknownValue(s) => serializer.serialize_str(s.as_str()),
            }
        }
    }
    impl Default for SkipShutdown {
        fn default() -> Self {
            Self::False
        }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct StorageProfile {
    #[doc = "Gets or sets the list of virtual disks associated with the virtual machine."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub disks: Vec<VirtualDisk>,
}
impl StorageProfile {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the resource update properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct StorageProfileUpdate {
    #[doc = "Gets or sets the list of virtual disks associated with the virtual machine."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub disks: Vec<VirtualDiskUpdate>,
}
impl StorageProfileUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The StorageQoSPolicy definition."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct StorageQosPolicy {
    #[doc = "The name of the policy."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "The ID of the QoS policy."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[doc = "The maximum IO operations per second."]
    #[serde(rename = "iopsMaximum", default, skip_serializing_if = "Option::is_none")]
    pub iops_maximum: Option<i64>,
    #[doc = "The minimum IO operations per second."]
    #[serde(rename = "iopsMinimum", default, skip_serializing_if = "Option::is_none")]
    pub iops_minimum: Option<i64>,
    #[doc = "The Bandwidth Limit for internet traffic."]
    #[serde(rename = "bandwidthLimit", default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_limit: Option<i64>,
    #[doc = "The underlying policy."]
    #[serde(rename = "policyId", default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}
impl StorageQosPolicy {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The StorageQoSPolicyDetails definition."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct StorageQosPolicyDetails {
    #[doc = "The name of the policy."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "The ID of the QoS policy."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
impl StorageQosPolicyDetails {
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
#[doc = "Virtual disk model"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualDisk {
    #[doc = "Gets or sets the name of the disk."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Gets the display name of the virtual disk as shown in the vmmServer. This is the fallback label for a disk when the name is not set."]
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[doc = "Gets or sets the disk id."]
    #[serde(rename = "diskId", default, skip_serializing_if = "Option::is_none")]
    pub disk_id: Option<String>,
    #[doc = "Gets or sets the disk total size."]
    #[serde(rename = "diskSizeGB", default, skip_serializing_if = "Option::is_none")]
    pub disk_size_gb: Option<i32>,
    #[doc = "Gets the max disk size."]
    #[serde(rename = "maxDiskSizeGB", default, skip_serializing_if = "Option::is_none")]
    pub max_disk_size_gb: Option<i32>,
    #[doc = "Gets or sets the disk bus."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<i32>,
    #[doc = "Gets or sets the disk lun."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lun: Option<i32>,
    #[doc = "Gets or sets the disk bus type."]
    #[serde(rename = "busType", default, skip_serializing_if = "Option::is_none")]
    pub bus_type: Option<String>,
    #[doc = "Gets or sets the disk vhd type."]
    #[serde(rename = "vhdType", default, skip_serializing_if = "Option::is_none")]
    pub vhd_type: Option<String>,
    #[doc = "Gets the disk volume type."]
    #[serde(rename = "volumeType", default, skip_serializing_if = "Option::is_none")]
    pub volume_type: Option<String>,
    #[doc = "Gets the disk vhd format type."]
    #[serde(rename = "vhdFormatType", default, skip_serializing_if = "Option::is_none")]
    pub vhd_format_type: Option<String>,
    #[doc = "Gets or sets the disk id in the template."]
    #[serde(rename = "templateDiskId", default, skip_serializing_if = "Option::is_none")]
    pub template_disk_id: Option<String>,
    #[doc = "The StorageQoSPolicyDetails definition."]
    #[serde(rename = "storageQoSPolicy", default, skip_serializing_if = "Option::is_none")]
    pub storage_qo_s_policy: Option<StorageQosPolicyDetails>,
    #[doc = "Create diff disk."]
    #[serde(rename = "createDiffDisk", default, skip_serializing_if = "Option::is_none")]
    pub create_diff_disk: Option<CreateDiffDisk>,
}
impl VirtualDisk {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Virtual Disk Update model"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualDiskUpdate {
    #[doc = "Gets or sets the name of the disk."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Gets or sets the disk id."]
    #[serde(rename = "diskId", default, skip_serializing_if = "Option::is_none")]
    pub disk_id: Option<String>,
    #[doc = "Gets or sets the disk total size."]
    #[serde(rename = "diskSizeGB", default, skip_serializing_if = "Option::is_none")]
    pub disk_size_gb: Option<i32>,
    #[doc = "Gets or sets the disk bus."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<i32>,
    #[doc = "Gets or sets the disk lun."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lun: Option<i32>,
    #[doc = "Gets or sets the disk bus type."]
    #[serde(rename = "busType", default, skip_serializing_if = "Option::is_none")]
    pub bus_type: Option<String>,
    #[doc = "Gets or sets the disk vhd type."]
    #[serde(rename = "vhdType", default, skip_serializing_if = "Option::is_none")]
    pub vhd_type: Option<String>,
    #[doc = "The StorageQoSPolicyDetails definition."]
    #[serde(rename = "storageQoSPolicy", default, skip_serializing_if = "Option::is_none")]
    pub storage_qo_s_policy: Option<StorageQosPolicyDetails>,
}
impl VirtualDiskUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the create checkpoint action properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualMachineCreateCheckpoint {
    #[doc = "Name of the checkpoint."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Description of the checkpoint."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
impl VirtualMachineCreateCheckpoint {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the delete checkpoint action properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualMachineDeleteCheckpoint {
    #[doc = "ID of the checkpoint to be deleted."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
impl VirtualMachineDeleteCheckpoint {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Define the virtualMachineInstance."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualMachineInstance {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<VirtualMachineInstanceProperties>,
    #[doc = "The extended location."]
    #[serde(rename = "extendedLocation")]
    pub extended_location: ExtendedLocation,
}
impl VirtualMachineInstance {
    pub fn new(extended_location: ExtendedLocation) -> Self {
        Self {
            proxy_resource: ProxyResource::default(),
            properties: None,
            extended_location,
        }
    }
}
#[doc = "The response of a VirtualMachineInstance list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualMachineInstanceListResult {
    #[doc = "The VirtualMachineInstance items on this page"]
    pub value: Vec<VirtualMachineInstance>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for VirtualMachineInstanceListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl VirtualMachineInstanceListResult {
    pub fn new(value: Vec<VirtualMachineInstance>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualMachineInstanceProperties {
    #[doc = "Availability Sets in vm."]
    #[serde(
        rename = "availabilitySets",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub availability_sets: Vec<AvailabilitySetListItem>,
    #[doc = "Defines the resource properties."]
    #[serde(rename = "osProfile", default, skip_serializing_if = "Option::is_none")]
    pub os_profile: Option<OsProfileForVmInstance>,
    #[doc = "Defines the resource properties."]
    #[serde(rename = "hardwareProfile", default, skip_serializing_if = "Option::is_none")]
    pub hardware_profile: Option<HardwareProfile>,
    #[doc = "Defines the resource properties."]
    #[serde(rename = "networkProfile", default, skip_serializing_if = "Option::is_none")]
    pub network_profile: Option<NetworkProfile>,
    #[doc = "Defines the resource properties."]
    #[serde(rename = "storageProfile", default, skip_serializing_if = "Option::is_none")]
    pub storage_profile: Option<StorageProfile>,
    #[doc = "Specifies the vmmServer infrastructure specific settings for the virtual machine instance."]
    #[serde(rename = "infrastructureProfile", default, skip_serializing_if = "Option::is_none")]
    pub infrastructure_profile: Option<InfrastructureProfile>,
    #[doc = "Gets the power state of the virtual machine."]
    #[serde(rename = "powerState", default, skip_serializing_if = "Option::is_none")]
    pub power_state: Option<String>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
}
impl VirtualMachineInstanceProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The type used for update operations of the VirtualMachineInstance."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualMachineInstanceUpdate {
    #[doc = "Virtual Machine Instance Properties Update model"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<VirtualMachineInstanceUpdateProperties>,
}
impl VirtualMachineInstanceUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Virtual Machine Instance Properties Update model"]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualMachineInstanceUpdateProperties {
    #[doc = "Availability Sets in vm."]
    #[serde(
        rename = "availabilitySets",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub availability_sets: Vec<AvailabilitySetListItem>,
    #[doc = "Defines the resource update properties."]
    #[serde(rename = "hardwareProfile", default, skip_serializing_if = "Option::is_none")]
    pub hardware_profile: Option<HardwareProfileUpdate>,
    #[doc = "Defines the resource update properties."]
    #[serde(rename = "networkProfile", default, skip_serializing_if = "Option::is_none")]
    pub network_profile: Option<NetworkProfileUpdate>,
    #[doc = "Defines the resource update properties."]
    #[serde(rename = "storageProfile", default, skip_serializing_if = "Option::is_none")]
    pub storage_profile: Option<StorageProfileUpdate>,
    #[doc = "Specifies the vmmServer infrastructure specific update settings for the virtual machine instance."]
    #[serde(rename = "infrastructureProfile", default, skip_serializing_if = "Option::is_none")]
    pub infrastructure_profile: Option<InfrastructureProfileUpdate>,
}
impl VirtualMachineInstanceUpdateProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The Virtual machine inventory item."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualMachineInventoryItem {
    #[serde(flatten)]
    pub inventory_item_properties: InventoryItemProperties,
    #[doc = "Virtual machine operating system type."]
    #[serde(rename = "osType", default, skip_serializing_if = "Option::is_none")]
    pub os_type: Option<OsType>,
    #[doc = "Gets os name."]
    #[serde(rename = "osName", default, skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
    #[doc = "Gets os version."]
    #[serde(rename = "osVersion", default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[doc = "Gets the power state of the virtual machine."]
    #[serde(rename = "powerState", default, skip_serializing_if = "Option::is_none")]
    pub power_state: Option<String>,
    #[doc = "Gets or sets the nic ip addresses."]
    #[serde(
        rename = "ipAddresses",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ip_addresses: Vec<String>,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<InventoryItemDetails>,
    #[doc = "Gets the bios guid."]
    #[serde(rename = "biosGuid", default, skip_serializing_if = "Option::is_none")]
    pub bios_guid: Option<String>,
    #[doc = "Gets the tracked resource id corresponding to the inventory resource."]
    #[serde(rename = "managedMachineResourceId", default, skip_serializing_if = "Option::is_none")]
    pub managed_machine_resource_id: Option<String>,
}
impl VirtualMachineInventoryItem {
    pub fn new(inventory_item_properties: InventoryItemProperties) -> Self {
        Self {
            inventory_item_properties,
            os_type: None,
            os_name: None,
            os_version: None,
            power_state: None,
            ip_addresses: Vec::new(),
            cloud: None,
            bios_guid: None,
            managed_machine_resource_id: None,
        }
    }
}
#[doc = "Defines the restore checkpoint action properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualMachineRestoreCheckpoint {
    #[doc = "ID of the checkpoint to be restored to."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
impl VirtualMachineRestoreCheckpoint {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The VirtualMachineTemplates resource definition."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualMachineTemplate {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<VirtualMachineTemplateProperties>,
    #[doc = "The extended location."]
    #[serde(rename = "extendedLocation")]
    pub extended_location: ExtendedLocation,
}
impl VirtualMachineTemplate {
    pub fn new(tracked_resource: TrackedResource, extended_location: ExtendedLocation) -> Self {
        Self {
            tracked_resource,
            properties: None,
            extended_location,
        }
    }
}
#[doc = "The Virtual machine template inventory item."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualMachineTemplateInventoryItem {
    #[serde(flatten)]
    pub inventory_item_properties: InventoryItemProperties,
    #[doc = "Gets the desired number of vCPUs for the vm."]
    #[serde(rename = "cpuCount", default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i32>,
    #[doc = "MemoryMB is the desired size of a virtual machine's memory, in MB."]
    #[serde(rename = "memoryMB", default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<i32>,
    #[doc = "Virtual machine operating system type."]
    #[serde(rename = "osType", default, skip_serializing_if = "Option::is_none")]
    pub os_type: Option<OsType>,
    #[doc = "Gets os name."]
    #[serde(rename = "osName", default, skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
}
impl VirtualMachineTemplateInventoryItem {
    pub fn new(inventory_item_properties: InventoryItemProperties) -> Self {
        Self {
            inventory_item_properties,
            cpu_count: None,
            memory_mb: None,
            os_type: None,
            os_name: None,
        }
    }
}
#[doc = "The response of a VirtualMachineTemplate list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualMachineTemplateListResult {
    #[doc = "The VirtualMachineTemplate items on this page"]
    pub value: Vec<VirtualMachineTemplate>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for VirtualMachineTemplateListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl VirtualMachineTemplateListResult {
    pub fn new(value: Vec<VirtualMachineTemplate>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualMachineTemplateProperties {
    #[doc = "Gets or sets the inventory Item ID for the resource."]
    #[serde(rename = "inventoryItemId", default, skip_serializing_if = "Option::is_none")]
    pub inventory_item_id: Option<String>,
    #[doc = "Unique ID of the virtual machine template."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[doc = "ARM Id of the vmmServer resource in which this resource resides."]
    #[serde(rename = "vmmServerId", default, skip_serializing_if = "Option::is_none")]
    pub vmm_server_id: Option<String>,
    #[doc = "Virtual machine operating system type."]
    #[serde(rename = "osType", default, skip_serializing_if = "Option::is_none")]
    pub os_type: Option<OsType>,
    #[doc = "Gets os name."]
    #[serde(rename = "osName", default, skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
    #[doc = "Gets computer name."]
    #[serde(rename = "computerName", default, skip_serializing_if = "Option::is_none")]
    pub computer_name: Option<String>,
    #[doc = "MemoryMB is the desired size of a virtual machine's memory, in MB."]
    #[serde(rename = "memoryMB", default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<i32>,
    #[doc = "Gets the desired number of vCPUs for the vm."]
    #[serde(rename = "cpuCount", default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i32>,
    #[doc = "Limit CPU for migration."]
    #[serde(rename = "limitCpuForMigration", default, skip_serializing_if = "Option::is_none")]
    pub limit_cpu_for_migration: Option<LimitCpuForMigration>,
    #[doc = "Dynamic memory enabled."]
    #[serde(rename = "dynamicMemoryEnabled", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_enabled: Option<DynamicMemoryEnabled>,
    #[doc = "Customizable."]
    #[serde(rename = "isCustomizable", default, skip_serializing_if = "Option::is_none")]
    pub is_customizable: Option<IsCustomizable>,
    #[doc = "Gets the max dynamic memory for the vm."]
    #[serde(rename = "dynamicMemoryMaxMB", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_max_mb: Option<i32>,
    #[doc = "Gets the min dynamic memory for the vm."]
    #[serde(rename = "dynamicMemoryMinMB", default, skip_serializing_if = "Option::is_none")]
    pub dynamic_memory_min_mb: Option<i32>,
    #[doc = "Highly available."]
    #[serde(rename = "isHighlyAvailable", default, skip_serializing_if = "Option::is_none")]
    pub is_highly_available: Option<IsHighlyAvailable>,
    #[doc = "Gets the generation for the vm."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i32>,
    #[doc = "Gets the network interfaces of the template."]
    #[serde(
        rename = "networkInterfaces",
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_interfaces: Vec<NetworkInterface>,
    #[doc = "Gets the disks of the template."]
    #[serde(
        default,
        deserialize_with = "azure_core::util::deserialize_null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub disks: Vec<VirtualDisk>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
}
impl VirtualMachineTemplateProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The type used for updating tags in VirtualMachineTemplate resources."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualMachineTemplateTagsUpdate {
    #[doc = "Resource tags."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl VirtualMachineTemplateTagsUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The VirtualNetworks resource definition."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualNetwork {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<VirtualNetworkProperties>,
    #[doc = "The extended location."]
    #[serde(rename = "extendedLocation")]
    pub extended_location: ExtendedLocation,
}
impl VirtualNetwork {
    pub fn new(tracked_resource: TrackedResource, extended_location: ExtendedLocation) -> Self {
        Self {
            tracked_resource,
            properties: None,
            extended_location,
        }
    }
}
#[doc = "The Virtual network inventory item."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualNetworkInventoryItem {
    #[serde(flatten)]
    pub inventory_item_properties: InventoryItemProperties,
}
impl VirtualNetworkInventoryItem {
    pub fn new(inventory_item_properties: InventoryItemProperties) -> Self {
        Self { inventory_item_properties }
    }
}
#[doc = "The response of a VirtualNetwork list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualNetworkListResult {
    #[doc = "The VirtualNetwork items on this page"]
    pub value: Vec<VirtualNetwork>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for VirtualNetworkListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl VirtualNetworkListResult {
    pub fn new(value: Vec<VirtualNetwork>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualNetworkProperties {
    #[doc = "Gets or sets the inventory Item ID for the resource."]
    #[serde(rename = "inventoryItemId", default, skip_serializing_if = "Option::is_none")]
    pub inventory_item_id: Option<String>,
    #[doc = "Unique ID of the virtual network."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[doc = "ARM Id of the vmmServer resource in which this resource resides."]
    #[serde(rename = "vmmServerId", default, skip_serializing_if = "Option::is_none")]
    pub vmm_server_id: Option<String>,
    #[doc = "Name of the virtual network in vmmServer."]
    #[serde(rename = "networkName", default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
}
impl VirtualNetworkProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The type used for updating tags in VirtualNetwork resources."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VirtualNetworkTagsUpdate {
    #[doc = "Resource tags."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl VirtualNetworkTagsUpdate {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Defines the HybridIdentityMetadata."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VmInstanceHybridIdentityMetadata {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[doc = "Describes the properties of Hybrid Identity Metadata for a Virtual Machine."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<VmInstanceHybridIdentityMetadataProperties>,
}
impl VmInstanceHybridIdentityMetadata {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The response of a VmInstanceHybridIdentityMetadata list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmInstanceHybridIdentityMetadataListResult {
    #[doc = "The VmInstanceHybridIdentityMetadata items on this page"]
    pub value: Vec<VmInstanceHybridIdentityMetadata>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for VmInstanceHybridIdentityMetadataListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl VmInstanceHybridIdentityMetadataListResult {
    pub fn new(value: Vec<VmInstanceHybridIdentityMetadata>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Describes the properties of Hybrid Identity Metadata for a Virtual Machine."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VmInstanceHybridIdentityMetadataProperties {
    #[doc = "The unique identifier for the resource."]
    #[serde(rename = "resourceUid", default, skip_serializing_if = "Option::is_none")]
    pub resource_uid: Option<String>,
    #[doc = "Gets or sets the Public Key."]
    #[serde(rename = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
}
impl VmInstanceHybridIdentityMetadataProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "Credentials to connect to VmmServer."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VmmCredential {
    #[doc = "Username to use to connect to VmmServer."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[doc = "Password to use to connect to VmmServer."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
impl VmmCredential {
    pub fn new() -> Self {
        Self::default()
    }
}
#[doc = "The VmmServers resource definition."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmmServer {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[doc = "Defines the resource properties."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<VmmServerProperties>,
    #[doc = "The extended location."]
    #[serde(rename = "extendedLocation")]
    pub extended_location: ExtendedLocation,
}
impl VmmServer {
    pub fn new(tracked_resource: TrackedResource, extended_location: ExtendedLocation) -> Self {
        Self {
            tracked_resource,
            properties: None,
            extended_location,
        }
    }
}
#[doc = "The response of a VmmServer list operation."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmmServerListResult {
    #[doc = "The VmmServer items on this page"]
    pub value: Vec<VmmServer>,
    #[doc = "The link to the next page of items"]
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl azure_core::Continuable for VmmServerListResult {
    type Continuation = String;
    fn continuation(&self) -> Option<Self::Continuation> {
        self.next_link.clone().filter(|value| !value.is_empty())
    }
}
impl VmmServerListResult {
    pub fn new(value: Vec<VmmServer>) -> Self {
        Self { value, next_link: None }
    }
}
#[doc = "Defines the resource properties."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmmServerProperties {
    #[doc = "Credentials to connect to VmmServer."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<VmmCredential>,
    #[doc = "Fqdn is the hostname/ip of the vmmServer."]
    pub fqdn: String,
    #[doc = "Port is the port on which the vmmServer is listening."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    #[doc = "Gets the connection status to the vmmServer."]
    #[serde(rename = "connectionStatus", default, skip_serializing_if = "Option::is_none")]
    pub connection_status: Option<String>,
    #[doc = "Gets any error message if connection to vmmServer is having any issue."]
    #[serde(rename = "errorMessage", default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[doc = "Unique ID of vmmServer."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[doc = "Version is the version of the vmmSever."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[doc = "The provisioning state of the resource."]
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
}
impl VmmServerProperties {
    pub fn new(fqdn: String) -> Self {
        Self {
            credentials: None,
            fqdn,
            port: None,
            connection_status: None,
            error_message: None,
            uuid: None,
            version: None,
            provisioning_state: None,
        }
    }
}
#[doc = "The type used for updating tags in VmmServer resources."]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct VmmServerTagsUpdate {
    #[doc = "Resource tags."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl VmmServerTagsUpdate {
    pub fn new() -> Self {
        Self::default()
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
