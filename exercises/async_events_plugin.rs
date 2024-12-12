use falco_plugin::anyhow::Error;
use falco_plugin::async_event::{AsyncEvent, AsyncEventPlugin, AsyncHandler};
use falco_plugin::base::Plugin;
use falco_plugin::event::events::{Event, EventMetadata};
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;

//
// INTRO
// The scope of this exercise is to introduce you the Async Events capability.
// You may want to check the documentation SDK documentation at
// https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/async_event/index.html
// and the proper section of the Falco documentation at
// https://falco.org/docs/plugins/architecture/#async-events-capability
//

// Have some static data to check in the test
const TEST_EVENT_NAME_C_STR: &CStr = c"async";
const TEST_EVENT_NAME: &str = "async";
const TEST_DATA: &[u8] = b"hello world";

struct AsyncRandomGenPlugin;

impl Plugin for AsyncRandomGenPlugin {
    const NAME: &'static CStr = c"async_random_generator";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"generates async events with random numbers";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/plugin-sdk-rs";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

// Implement async event capability
// DOCS: https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/async_event/trait.AsyncEventPlugin.html
impl AsyncEventPlugin for AsyncRandomGenPlugin {
    // Async plugin has to declare which events they send
    const ASYNC_EVENTS: &'static [&'static str] = &[TEST_EVENT_NAME];
    // Async events can be injected to any kind of source, or to specific ones
    // When empty, attach to all event sources
    const EVENT_SOURCES: &'static [&'static str] = &[];

    // This is useful when we have a background mechanism to generate the events.
    // In this example we're not doing that.
    // The SDK provides a helper, you may want to check it:
    // https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/async_event/struct.BackgroundTask.html
    fn start_async(&mut self, handler: AsyncHandler) -> Result<(), Error> {
        // create an async event
        let event = AsyncEvent {
            plugin_id: None,
            // TODO fill the event
        };
        let metadata = EventMetadata::default();
        let event = Event {
            metadata,
            params: event,
        };

        // and submit it to the main event loop
        handler.emit(event)?;
        Ok(())
    }

    fn stop_async(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

static_plugin!(MY_SOURCE_PLUGIN = AsyncRandomGenPlugin);

fn main() {
    // just needed to build the exercise
}

// These are the tests your plugin needs to pass. For now, we have just one: it should
// successfully load into the test harness (emulating Falco plugin API) and get a valid event
mod tests {
    use crate::{TEST_DATA, TEST_EVENT_NAME_C_STR};

    use exercises::native::NativeTestDriver;
    use exercises::{CapturingTestDriver, TestDriver};
    use falco_plugin::event::events::types::PPME_ASYNCEVENT_E;
    use falco_plugin::event::events::RawEvent;

    #[test]
    fn get_event() {
        let mut driver = NativeTestDriver::new().unwrap();
        driver
            .register_plugin(&super::MY_SOURCE_PLUGIN, c"")
            .unwrap();
        let mut driver = driver.start_capture(c"", c"").unwrap();

        let next = driver.next_event();
        assert!(next.is_ok());

        // NativeTestDriver doesn't have much features, in order to be
        // as much indepentent as possible from the SDK, so here we
        // manually convert the falco_plugin_runner::event::Event to
        // falco_event::events::event
        let evt = next.unwrap().to_event_input();
        let evt = unsafe { RawEvent::from_ptr(evt.evt as *const _) }.unwrap();
        let evt = evt.load::<PPME_ASYNCEVENT_E>();
        assert!(evt.is_ok());
        // Check the fields we set in the event
        let evt = evt.unwrap().params;
        assert!(evt.plugin_id.is_some());
        assert!(evt.name.is_some());
        assert!(evt.data.is_some());
        assert_eq!(evt.plugin_id.unwrap(), 0);
        assert_eq!(evt.name.unwrap(), TEST_EVENT_NAME_C_STR);
        assert_eq!(evt.data.unwrap(), TEST_DATA);
    }
}
