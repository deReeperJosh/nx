use crate::ipc::sf;
use crate::version;

use super::FileSystem;

ipc_sf_define_default_client_for_interface!(FileSystemProxy);
ipc_sf_define_interface_trait! {
    trait FileSystemProxy {
        set_current_process [1, version::VersionInterval::all()]: (process_id: sf::ProcessId) =>  () ();
        open_sd_card_filesystem [18, version::VersionInterval::all()]: () => (sd_filesystem: FileSystem) (sd_filesystem: FileSystem);
        output_access_log_to_sd_card [1006, version::VersionInterval::all()]: (log_buf: sf::InMapAliasBuffer<u8>) =>  () ();
    }
}
