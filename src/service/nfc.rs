use crate::ipc::sf::sm;
use crate::result::*;
use crate::service;

pub use crate::ipc::sf::nfc::*;

impl service::IService for UserManager {
    fn get_name() -> sm::ServiceName {
        sm::ServiceName::new("nfc:user")
    }

    fn as_domain() -> bool {
        true
    }

    fn post_initialize(&mut self) -> Result<()> {
        Ok(())
    }
}

impl service::IService for SystemManager {
    fn get_name() -> sm::ServiceName {
        sm::ServiceName::new("nfc:sys")
    }

    fn as_domain() -> bool {
        true
    }

    fn post_initialize(&mut self) -> Result<()> {
        Ok(())
    }
}

impl service::IService for MifareManager {
    fn get_name() -> sm::ServiceName {
        sm::ServiceName::new("nfc:mf:u")
    }

    fn as_domain() -> bool {
        true
    }

    fn post_initialize(&mut self) -> Result<()> {
        Ok(())
    }
}
