use std::ffi::CStr;

pub mod native;

pub mod common;
pub mod syscall_source_plugin;

pub use common::*;

pub fn init_plugin<D: TestDriver>(
    api: &'static falco_plugin::api::plugin_api,
    config: &CStr,
) -> falco_plugin::anyhow::Result<(D, D::Plugin)> {
    let mut driver = D::new()?;
    let plugin = driver.register_plugin(api, config)?;

    Ok((driver, plugin))
}
