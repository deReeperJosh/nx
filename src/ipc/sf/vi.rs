use crate::ipc::sf;
use crate::util;
use crate::version;

use super::applet::AppletResourceUserId;

use nx_derive::{Request, Response};

pub type DisplayName = util::ArrayString<0x40>;

define_bit_enum! {
    LayerFlags (u32) {
        None = 0,
        Default = bit!(0)
    }
}

/// Tells the display service how to scale spawned layers.
#[derive(Request, Response, Copy, Clone, Debug, Default)]
#[repr(u64)]
pub enum ScalingMode {
    None = 0,
    #[default]
    FitToLayer = 2,
    PreserveAspectRatio = 4,
}

pub type DisplayId = u64;

pub type LayerId = u64;

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum DisplayServiceMode {
    User = 0,
    Privileged = 1,
}

#[derive(Request, Response, Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(u32)]
pub enum LayerStackId {
    #[default]
    Default,
    Lcd,
    Screenshot,
    Recording,
    LastFrame,
    Arbitrary,
    ApplicationForDebug,
    Null,
}

ipc_sf_define_default_client_for_interface!(ManagerDisplay);
ipc_sf_define_interface_trait! {
    trait ManagerDisplay {
        create_managed_layer [2010, version::VersionInterval::all(), mut]: (flags: LayerFlags, display_id: DisplayId, raw_aruid: u64) =>  (id: LayerId) (id: LayerId);
        destroy_managed_layer [2011, version::VersionInterval::all()]: (id: LayerId) =>  () ();
        add_to_layer_stack [6000, version::VersionInterval::all()]: (stack: LayerStackId, layer: LayerId) =>  () ();
    }
}

ipc_sf_define_default_client_for_interface!(SystemDisplay);
ipc_sf_define_interface_trait! {
    trait SystemDisplay {
        get_z_order_count_min [1200, version::VersionInterval::all()]: (display_id: DisplayId) =>  (z: i64) (z: i64);
        get_z_order_count_max [1202, version::VersionInterval::all()]: (display_id: DisplayId) =>  (z: i64) (z: i64);
        set_layer_position [2201, version::VersionInterval::all(), mut]: (x: f32, y: f32, id: LayerId) =>  () ();
        set_layer_size [2203, version::VersionInterval::all(), mut]: (id: LayerId, width: u64, height: u64) =>  () ();
        set_layer_z [2205, version::VersionInterval::all(), mut]: (id: LayerId, z: i64) =>  () ();
        set_layer_visibility [2207, version::VersionInterval::all(), mut]: (visible: bool, id: LayerId) =>  () ();
    }
}

ipc_sf_define_default_client_for_interface!(ApplicationDisplay);
ipc_sf_define_interface_trait! {
    trait ApplicationDisplay {
        get_relay_service [100, version::VersionInterval::all()]: () => (relay_service: sf::dispdrv::HOSBinderDriver) (relay_service: sf::dispdrv::HOSBinderDriver);
        get_system_display_service [101, version::VersionInterval::all()]: () => (system_display_service: SystemDisplay) (system_display_service: session_type!(SystemDisplay));
        get_manager_display_service [102, version::VersionInterval::all()]: () => (manager_display_service: ManagerDisplay) (manager_display_service: session_type!(ManagerDisplay));
        open_display [1010, version::VersionInterval::all(), mut]: (name: DisplayName) =>  (id: DisplayId) (id: DisplayId);
        close_display [1020, version::VersionInterval::all(), mut]: (id: DisplayId) =>  () ();
        open_layer [2020, version::VersionInterval::all(), mut]: (name: DisplayName, id: LayerId, aruid: AppletResourceUserId, out_native_window: sf::OutMapAliasBuffer<u8>) =>  (native_window_size: usize) (native_window_size: usize);
        set_scaling_mode [2101, version::VersionInterval::all(), mut]: (scaling_mode: ScalingMode, layer_id: LayerId)  => ()  ();
        create_stray_layer [2030, version::VersionInterval::all(), mut]: (flags: LayerFlags, display_id: DisplayId, out_native_window: sf::OutMapAliasBuffer<u8>) =>  (id: LayerId, native_window_size: usize) (id: LayerId, native_window_size: usize);
        destroy_stray_layer [2031, version::VersionInterval::all(), mut]: (id: LayerId) =>  () ();
        get_display_vsync_event [5202, version::VersionInterval::all()]: (id: DisplayId) =>  (event_handle: sf::CopyHandle) (event_handle: sf::CopyHandle);
    }
}

//ipc_sf_define_default_client_for_interface!(ApplicationRootService);
ipc_sf_define_interface_trait! {
    trait ApplicationDisplayRoot {
        get_display_service [0, version::VersionInterval::all()]: (mode: DisplayServiceMode) =>  (display_service: ApplicationDisplay) (display_service: session_type!(ApplicationDisplay));
    }
}

ipc_sf_define_interface_trait! {
    trait SystemDisplayRoot {
        get_display_service [1, version::VersionInterval::all()]: (mode: DisplayServiceMode) =>  (display_service: ApplicationDisplay) (display_service: session_type!(ApplicationDisplay));
    }
}

ipc_sf_define_interface_trait! {
    trait ManagerDisplayRoot {
        get_display_service [2, version::VersionInterval::all()]: (mode: DisplayServiceMode) =>  (display_service: ApplicationDisplay) (display_service: session_type!(ApplicationDisplay));
    }
}

pub(crate) trait CommonDisplayRootClient {
    fn get_display_service(&self) -> crate::result::Result<ApplicationDisplay>;
}