use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::EventType::{
    SYSCALL_CLOSE_E, SYSCALL_OPEN_X, SYSCALL_READ_E,
};
use falco_plugin::event::events::types::{
    EventType, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_OPEN_X, PPME_SYSCALL_READ_E,
};
use falco_plugin::event::fields::types::PT_FD;
use falco_plugin::extract::{field, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;

// INTRO
// The goal of this exercise is to write an extract plugin that works with system call events,
// e.g. coming from a kernel driver. Unlike plugin events, system call events have a predefined
// schema and all such events can be parsed into strongly-typed structs.
//
// DOCS:
// * https://falcosecurity.github.io/plugin-sdk-rs/falco_event/events/types/index.html
// * https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/extract/trait.ExtractPlugin.html#associatedconstant.EXTRACT_FIELDS

struct SyscallExtractPlugin;

// Plugin metadata
impl Plugin for SyscallExtractPlugin {
    const NAME: &'static CStr = c"syscall-extract";
    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    const DESCRIPTION: &'static CStr = c"sample extract plugin for syscall events";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/plugin-sdk-rs";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

/// # A helper function to convert an FD parameter to u64 (or an error)
///
/// We need to unwrap two layers of indirection:
/// - Option (since all event parameters are optional)
/// - the PT_FD newtype wrapper (many PT_* types are wrappers over the underlying type,
///   like i64, that provide extra functionality like formatting according to Falco conventions)
///
/// Then we need to cast the i64 to u64, since the plugin API does not allow returning
/// signed values
fn unwrap_fd(fd: Option<PT_FD>) -> Result<u64, Error> {
    if let Some(fd) = fd {
        Ok(fd.0 as u64)
    } else {
        falco_plugin::anyhow::bail!("fd not present")
    }
}

impl SyscallExtractPlugin {
    // Extract the file descriptor number from an event if possible
    fn extract_fd(&mut self, ctx: ExtractRequest<Self>) -> Result<u64, Error> {
        // Get the RawEvent from the extract request. A RawEvent only involves parsing
        // the event header, all the parameters remain represented as a raw byte buffer.
        let event = ctx.event.event()?;

        // To get to the strongly-typed events, we need to check the event type and parse
        // the event according to it. The two steps are combined into the RawEvent::load
        // method, which returns an Event<T> if the raw event is actually a T (e.g. an OPEN_X
        // event), or an error otherwise.
        //
        // Once you have an Event, the parameters are accessible as struct fields under `params`.
        //
        // TODO: make sure you handle PPME_SYSCALL_READ_E and PPME_SYSCALL_CLOSE_E here as well
        if let Ok(ev) = event.load::<PPME_SYSCALL_OPEN_X>() {
            unwrap_fd(ev.params.fd)
        } else {
            falco_plugin::anyhow::bail!("could not find fd field")
        }
    }
}

impl ExtractPlugin for SyscallExtractPlugin {
    // The event types we are interested in. This avoids overhead by not calling your plugin
    // for events it's not prepared to handle. Note we use the SYSCALL_* constants here,
    // not the PPME_SYSCALL_* types.
    //
    // TODO: make sure you include SYSCALL_READ_E and SYSCALL_CLOSE_E in the filter
    const EVENT_TYPES: &'static [EventType] = &[SYSCALL_OPEN_X];

    // The event sources we want to process events from. `syscall` is a predefined name
    // for system call events
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] =
        &[field("rustlings.fd", &Self::extract_fd)];
}

static_plugin!(SYSCALL_EXTRACT_PLUGIN = SyscallExtractPlugin);

fn main() {}

mod tests {
    use exercises::native::NativeTestDriver;
    use exercises::{CapturingTestDriver, TestDriver};

    #[test]
    fn test_syscall_extract_plugin() {
        let mut driver = NativeTestDriver::new().unwrap();
        driver
            .register_plugin(&exercises::syscall_source_plugin::PLUGIN, c"")
            .unwrap();
        driver
            .register_plugin(&super::SYSCALL_EXTRACT_PLUGIN, c"")
            .unwrap();
        let mut driver = driver.start_capture(c"", c"").unwrap();

        let mut evts = 0;
        loop {
            let next = driver.next_event();
            let evt = match next {
                Ok(evt) => evt,
                Err(_) => break,
            };

            let field_as_str = driver.event_field_as_string(c"rustlings.fd", &evt);
            match evt.evt_num {
                // these events don't carry fd information
                Some(3) | Some(5) => assert!(field_as_str.unwrap().is_none()),

                // all others should return 5 as the fd number, so check that
                _ => assert_eq!(field_as_str.unwrap().unwrap(), "5"),
            }

            evts += 1;
        }

        assert_eq!(evts, 5);
    }
}
