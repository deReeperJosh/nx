use crate::ipc::sf;
use crate::version;

use nx_derive::{Request, Response};

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum RefcountType {
    Weak,
    Strong,
}

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum ParcelTransactionId {
    RequestBuffer = 1,
    SetBufferCount = 2,
    DequeueBuffer = 3,
    DetachBuffer = 4,
    DetachNextBuffer = 5,
    AttachBuffer = 6,
    QueueBuffer = 7,
    CancelBuffer = 8,
    Query = 9,
    Connect = 10,
    Disconnect = 11,
    SetSidebandStream = 12,
    AllocateBuffers = 13,
    SetPreallocatedBuffer = 14,
}

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum NativeHandleType {
    BufferEvent = 0xF,
}

pub type BinderHandle = i32;

ipc_sf_define_default_client_for_interface!(HOSBinderDriver);
ipc_sf_define_interface_trait! {
    trait HOSBinderDriver {
        transact_parcel [0, version::VersionInterval::all()]: (binder_handle: BinderHandle, transaction_id: ParcelTransactionId, flags: u32, in_parcel: sf::InMapAliasBuffer<u8>, out_parcel: sf::OutMapAliasBuffer<u8>) =>  () ();
        adjust_refcount [1, version::VersionInterval::all()]: (binder_handle: BinderHandle, add_value: i32, refcount_type: RefcountType) =>  () ();
        get_native_handle [2, version::VersionInterval::all()]: (binder_handle: BinderHandle, handle_type: NativeHandleType) =>  (native_handle: sf::CopyHandle) (native_handle: sf::CopyHandle);
        transact_parcel_auto [3, version::VersionInterval::from(version::Version::new(3,0,0))]: (binder_handle: BinderHandle, transaction_id: ParcelTransactionId, flags: u32, in_parcel: sf::InAutoSelectBuffer<u8>, out_parcel: sf::OutAutoSelectBuffer<u8>) =>  () ();
    }
}
