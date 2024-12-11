use falco_plugin::anyhow::{bail, Error};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::PPME_PLUGINEVENT_E;
use falco_plugin::extract::EventInput;
use falco_plugin::source::{EventBatch, SourcePlugin, SourcePluginInstance};
use falco_plugin::strings::CStringWriter;
use falco_plugin::tables::TablesInput;
use falco_plugin::{static_plugin, FailureReason};
use std::ffi::{CStr, CString};
use std::io::Write;

//
// INTRO
// The scope of this exercise is to introduce you the concept of source plugins.
// You may want to check the documentation for Source Plugins at
// https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/source/
//

// This is the type that represents your first plugin. It does not have any fields,
// because we do not need to store any state yet.
struct MySourcePlugin;

// Metadata for our plugin, you know the drill :)
impl Plugin for MySourcePlugin {
    const NAME: &'static CStr = c"noop-plugin";
    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    const DESCRIPTION: &'static CStr = c"The simplest possible plugin";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/plugin-sdk-rs";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

// An instance of our event source; this one doesn't need any state yet either
struct MySourceInstance;

// Add event sourcing capability to our plugin
//
// This lets the plugin emit events that can be later matched by Falco rules to raise alerts.
// (we don't have a way to write rules against this plugin yet, but stay tuned).
//
// Source plugins need two separate types: the plugin itself and an instance, responsible
// for actually generating events (this reflects the underlying API)
//
// DOCS: https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/source/trait.SourcePlugin.html
impl SourcePlugin for MySourcePlugin {
    // The instance type. These must match 1:1 with plugins (each source plugin has its own
    // instance type).
    type Instance = MySourceInstance;

    // Event source name. This is used by other plugins that wish to process events generated
    // by our plugin.
    const EVENT_SOURCE: &'static CStr = c"rustlings";

    // Plugin ID. Real plugins need to have an ID assigned via https://github.com/falcosecurity/plugins
    // but since we don't distribute our plugin anywhere, we can pick whatever we want, except zero
    // (that is reserved for system call sources).
    const PLUGIN_ID: u32 = 999;

    // Create a new instance
    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(MySourceInstance)
    }

    // Provide a string representation of an event
    //
    // Whenever you use %evt.plugininfo in your Falco rules, this method will be called
    // to render your event as a string.
    // Non-syscall sources are limited to emitting PPME_PLUGINEVENT_E events only, which have two fields:
    // - plugin_id, which is just our plugin id, as defined above
    // - event_data, which is an arbitrary byte buffer
    //
    // It's entirely up to you how you use the event_data field: it can be a (C-style)
    // string, a serialized data structure (JSON, bitcode, or anything else) etc.
    // In this example, we assume it's just a string.
    // If %evt.plugininfo doesn't ring any bell, check:
    // https://falco.org/docs/reference/rules/supported-fields/#field-class-evt
    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
        // Make sure we have a plugin event and parse it into individual fields
        let event = event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;

        if event.params.plugin_id != Some(Self::PLUGIN_ID) {
            // Falco shouldn't call this method for events from other plugins
            bail!("Plugin IDs don't match");
        }

        // All event fields are optional, so we have to check if the data is actually there
        match event.params.event_data {
            Some(payload) => {
                // CStringWriter is a small helper that lets you write arbitrary data
                // (e.g. using format strings) into CStrings. Note that as CStrings cannot
                // contain NUL bytes, any attempt to write one will fail.
                let mut writer = CStringWriter::default();
                writer.write_all(payload)?;
                Ok(writer.into_cstring())
            }
            None => Ok(CString::new("<no payload>")?),
        }
    }
}

// Now let's make this struct an actual source plugin instance type.
// For now, we want our plugin to exit immediately without generating any events,
// by returning `Err(FailureReason::Eof)?`
//
// DOCS: https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/source/trait.SourcePluginInstance.html
impl SourcePluginInstance for MySourceInstance {
    // The plugin type
    type Plugin = MySourcePlugin;

    fn next_batch(
        &mut self,
        _plugin: &mut Self::Plugin,
        _batch: &mut EventBatch,
    ) -> Result<(), Error> {
        Err(FailureReason::Eof)?
    }
}

static_plugin!(MY_SOURCE_PLUGIN = MySourcePlugin);

fn main() {
    // just needed to build the exercise
}

// These are the tests your plugin needs to pass. For now, we have just one: it should
// successfully load into the test harness (emulating Falco plugin API) and return EOF
// without generating any events
mod tests {
    use exercises::native::NativeTestDriver;
    use exercises::{CapturingTestDriver, TestDriver};

    #[test]
    fn no_events() {
        let mut driver = NativeTestDriver::new().unwrap();
        driver
            .register_plugin(&super::MY_SOURCE_PLUGIN, c"")
            .unwrap();
        let mut driver = driver.start_capture(c"", c"").unwrap();

        let next = driver.next_event();
        assert!(matches!(next, Err(falco_plugin_runner::ScapStatus::Eof)))
    }
}
