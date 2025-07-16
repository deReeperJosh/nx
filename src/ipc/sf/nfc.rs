use crate::ipc::sf;
use crate::ipc::sf::applet;
use crate::ipc::sf::hid;
use crate::version;

use nx_derive::{Request, Response};

pub mod rc;

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct DeviceHandle {
    pub id: u32,
    pub reserved: [u8; 4],
}
const_assert!(core::mem::size_of::<DeviceHandle>() == 0x8);

#[derive(Request, Response, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum State {
    NonInitialized = 0,
    Initialized = 1,
}

#[derive(Request, Response, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceState {
    Initialized = 0,
    SearchingForTag = 1,
    TagFound = 2,
    TagRemoved = 3,
    TagMounted = 4,
    Unavailable = 5,
    Finalized = 6,
}

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct TagInfo {
    pub uuid: [u8; 10],
    pub uuid_length: u8,
    pub reserved_1: [u8; 0x15],
    pub protocol: u32,
    pub tag_type: u32,
    pub reserved_2: [u8; 0x30],
}
const_assert!(core::mem::size_of::<TagInfo>() == 0x58);

define_bit_set! {
    Protocol (u32) {
        None = bit!(0),
        TypeA = bit!(1),
        TypeB = bit!(2),
        TypeF = bit!(3),
        All = 0xFFFFFFFF
    }
}

define_bit_set! {
    TagType (u32) {
        None = bit!(0),
        Type1 = bit!(1),
        Type2 = bit!(2),
        Type3 = bit!(3),
        Type4A = bit!(4),
        Type4B = bit!(5),
        Mifare = bit!(6),
        All = 0xFFFFFFFF
    }
}

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MifareCommand {
    Read = 0x30,
    AuthA = 0x60,
    AuthB = 0x61,
    Write = 0xA0,
    Transfer = 0xB0,
    Decrement = 0xC0,
    Increment = 0xC1,
    Store = 0xC2,
}

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct NfcSectorKey {
    pub mifare_command: u8,
    pub unknown: u8,
    pub reserved: [u8; 6],
    pub key: [u8; 6],
    pub reserved2: [u8; 2],
}
const_assert!(core::mem::size_of::<NfcSectorKey>() == 0x10);

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct NfcMifareReadBlockParameter {
    pub block_number: u8,
    pub reserved: [u8; 7],
    pub sector_key: NfcSectorKey,
}
const_assert!(core::mem::size_of::<NfcMifareReadBlockParameter>() == 0x18);

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct NfcMifareReadBlockData {
    pub data: [u8; 16],
    pub block_number: u8,
    pub reserved: [u8; 7],
}
const_assert!(core::mem::size_of::<NfcMifareReadBlockData>() == 0x18);

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct NfcMifareWriteBlockParameter {
    pub data: [u8; 16],
    pub block_number: u8,
    pub reserved: [u8; 7],
    pub sector_key: NfcSectorKey,
}
const_assert!(core::mem::size_of::<NfcMifareWriteBlockParameter>() == 0x28);

ipc_sf_define_default_client_for_interface!(Mifare);
ipc_sf_define_interface_trait! {
    trait Mifare {
        initialize [0, version::VersionInterval::all()]: () =>  () ();
        finalize [1, version::VersionInterval::all()]: () => () ();
        list_devices [2, version::VersionInterval::all()]: (out_devices: sf::OutPointerBuffer<DeviceHandle>) =>  (count: u32) (count: u32);
        start_detection [3, version::VersionInterval::all()]: (device_handle: DeviceHandle) =>  () ();
        stop_detection [4, version::VersionInterval::all()]: (device_handle: DeviceHandle) =>  () ();
        read_mifare [5, version::VersionInterval::all()]: (device_handle: DeviceHandle, out_read_data: sf::OutFixedPointerBuffer<NfcMifareReadBlockData>, in_read_param: sf::InFixedPointerBuffer<NfcMifareReadBlockParameter>) =>  () ();
        write_mifare [6, version::VersionInterval::all()]: (device_handle: DeviceHandle, in_write_param: sf::InFixedPointerBuffer<NfcMifareWriteBlockParameter>) =>  () ();
        get_tag_info [7, version::VersionInterval::all()]: (device_handle: DeviceHandle, out_tag_info: sf::OutFixedPointerBuffer<TagInfo>) =>  () ();
        attach_activate_event [8, version::VersionInterval::all()]: (device_handle: DeviceHandle) =>  (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
        attach_deactivate_event [9, version::VersionInterval::all()]: (device_handle: DeviceHandle) =>  (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
        get_state [10, version::VersionInterval::all()]: () => (state: State) (state: State);
        get_device_state [11, version::VersionInterval::all()]: (device_handle: DeviceHandle) =>  (device_state: DeviceState) (device_state: DeviceState);
        get_npad_id [12, version::VersionInterval::all()]: (device_handle: DeviceHandle) =>  (npad_id: hid::NpadIdType) (npad_id: hid::NpadIdType);
        attach_availability_change_event [13, version::VersionInterval::all()]: () => (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
    }
}

ipc_sf_define_default_client_for_interface!(MifareManager);
ipc_sf_define_interface_trait! {
    trait MifareManager {
        create_user_interface [0, version::VersionInterval::all()]: () => (user_interface: Mifare) (user_interface: session_type!(Mifare));
    }
}

ipc_sf_define_default_client_for_interface!(User);
ipc_sf_define_interface_trait! {
    trait User {
        initialize [0, version::VersionInterval::all()]: (aruid: applet::AppletResourceUserId) =>  () ();
        finalize [1, version::VersionInterval::all()]: () => () ();
        list_devices [2, version::VersionInterval::from(version::Version::new(4,0,0))]: (out_devices: sf::OutPointerBuffer<DeviceHandle>) =>  (count: u32) (count: u32);
        start_detection [3, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  () ();
        stop_detection [4, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  () ();
        read_mifare [5, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle, out_read_data: sf::OutFixedPointerBuffer<NfcMifareReadBlockData>, in_read_param: sf::InFixedPointerBuffer<NfcMifareReadBlockParameter>) =>  () ();
        write_mifare [6, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle, in_write_param: sf::InFixedPointerBuffer<NfcMifareWriteBlockParameter>) =>  () ();
        get_tag_info [7, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle, out_tag_info: sf::OutFixedPointerBuffer<TagInfo>) =>  () ();
        attach_activate_event [8, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
        attach_deactivate_event [9, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
        get_state [10, version::VersionInterval::from(version::Version::new(4,0,0))]: () => (state: State) (state: State);
        get_device_state [11, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  (device_state: DeviceState) (device_state: DeviceState);
        get_npad_id [12, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  (npad_id: hid::NpadIdType) (npad_id: hid::NpadIdType);
        attach_availability_change_event [13, version::VersionInterval::from(version::Version::new(4,0,0))]: () => (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
    }
}

ipc_sf_define_default_client_for_interface!(UserManager);
ipc_sf_define_interface_trait! {
    trait UserManager {
        create_user_interface [0, version::VersionInterval::all()]: () => (user_interface: User) (user_interface: session_type!(User));
    }
}

ipc_sf_define_default_client_for_interface!(System);
ipc_sf_define_interface_trait! {
    trait System {
        initialize [0, version::VersionInterval::all()]: (aruid: applet::AppletResourceUserId) =>  () ();
        finalize [1, version::VersionInterval::all()]: () => () ();
        list_devices [2, version::VersionInterval::from(version::Version::new(4,0,0))]: (out_devices: sf::OutPointerBuffer<DeviceHandle>) =>  (count: u32) (count: u32);
        start_detection [3, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  () ();
        stop_detection [4, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  () ();
        read_mifare [5, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle, out_read_data: sf::OutFixedPointerBuffer<NfcMifareReadBlockData>, in_read_param: sf::InFixedPointerBuffer<NfcMifareReadBlockParameter>) =>  () ();
        write_mifare [6, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle, in_write_param: sf::InFixedPointerBuffer<NfcMifareWriteBlockParameter>) =>  () ();
        get_tag_info [7, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle, out_tag_info: sf::OutFixedPointerBuffer<TagInfo>) =>  () ();
        attach_activate_event [8, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
        attach_deactivate_event [9, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
        get_state [10, version::VersionInterval::from(version::Version::new(4,0,0))]: () => (state: State) (state: State);
        get_device_state [11, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  (device_state: DeviceState) (device_state: DeviceState);
        get_npad_id [12, version::VersionInterval::from(version::Version::new(4,0,0))]: (device_handle: DeviceHandle) =>  (npad_id: hid::NpadIdType) (npad_id: hid::NpadIdType);
        attach_availability_change_event [13, version::VersionInterval::from(version::Version::new(4,0,0))]: () => (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
    }
}

ipc_sf_define_default_client_for_interface!(SystemManager);
ipc_sf_define_interface_trait! {
    trait SystemManager {
        create_system_interface [0, version::VersionInterval::all()]: () => (system_interface: System) (system_interface: session_type!(System));
    }
}
