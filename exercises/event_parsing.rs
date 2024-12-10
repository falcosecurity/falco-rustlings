use falco_plugin::anyhow::{anyhow, Error};
use falco_plugin::base::{Json, Plugin};
use falco_plugin::event::events::types::{EventType, PPME_PLUGINEVENT_E};
use falco_plugin::extract::{field, EventInput, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::parse::{ParseInput, ParsePlugin};
use falco_plugin::schemars::JsonSchema;
use falco_plugin::serde::Deserialize;
use falco_plugin::source::{EventBatch, PluginEvent, SourcePlugin, SourcePluginInstance};
use falco_plugin::static_plugin;
use falco_plugin::strings::CStringWriter;
use falco_plugin::tables::TablesInput;
use rand::Rng;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io::Write;

struct RandomGenPlugin {
    /// Specifies the range within witch the random
    /// value is generated. The range must be set
    /// from the plugin configuration.
    range: u64,

    /// Keep track of all numbers generated with how
    /// many times each one occurred
    histogram: BTreeMap<u64, u64>,
}

#[derive(JsonSchema, Deserialize)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
struct Config {
    /// Defines the random generator range.
    range: u64,
}

/// Plugin metadata
impl Plugin for RandomGenPlugin {
    const NAME: &'static CStr = c"random_generator";
    const PLUGIN_VERSION: &'static CStr = c"0.0.0";
    const DESCRIPTION: &'static CStr = c"generates a continuous stream of random numbers";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/plugin-sdk-rs";
    type ConfigType = Json<Config>;

    fn new(_input: Option<&TablesInput>, Json(config): Self::ConfigType) -> Result<Self, Error> {
        Ok(Self {
            range: config.range,
            histogram: BTreeMap::new(),
        })
    }

    fn set_config(&mut self, _config: Self::ConfigType) -> Result<(), Error> {
        Ok(())
    }
}

/// Plugin instance
struct RandomGenPluginInstance;

/// Implement SourcePluginInstance and generate the events
impl SourcePluginInstance for RandomGenPluginInstance {
    type Plugin = RandomGenPlugin;

    /// # Fill the next batch of events
    ///
    /// This is the most important method for the source plugin implementation. It is responsible
    /// for actually generating the events for the main event loop.
    ///
    /// For performance, events are returned in batches. Of course, it's entirely valid to have
    /// just a single event in a batch.
    ///
    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        let num: u64 = rng.gen_range(0..plugin.range);

        let event = num.to_le_bytes().to_vec();

        // Add the encoded u64 value to the batch
        let event = Self::plugin_event(&event);
        batch.add(event)?;

        Ok(())
    }
}

/// Event sourcing capability
impl SourcePlugin for RandomGenPlugin {
    type Instance = RandomGenPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"random_generator";
    const PLUGIN_ID: u32 = 1423;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(RandomGenPluginInstance)
    }

    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
        // Make sure we have a plugin event and parse it into individual fields
        let event = event.event()?;
        let event = event.load::<PPME_PLUGINEVENT_E>()?;

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

impl RandomGenPlugin {
    /// Reads the raw event payload and converts it to u64 value.
    fn extract_number(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event = req.event.event()?;
        let event = event.load::<PluginEvent>()?;
        let buf = event
            .params
            .event_data
            .ok_or_else(|| anyhow!("Missing event data"))?;
        Ok(u64::from_le_bytes(buf.try_into()?))
    }

    fn extract_count(&mut self, _req: ExtractRequest<Self>, num: u64) -> Result<u64, Error> {
        // Get the count of occurrences of `num` from `self.histogram`.
        // If the number isn't there (hasn't been generated even once),
        // return zero
        todo!()
    }
}

/// Event Parsing Capability
impl ParsePlugin for RandomGenPlugin {
    const EVENT_TYPES: &'static [EventType] = &[]; // inspect all events...
    const EVENT_SOURCES: &'static [&'static str] = &["random_generator"]; // ... from this plugin's source

    fn parse_event(&mut self, event: &EventInput, _parse_input: &ParseInput) -> Result<(), Error> {
        let event = event.event()?;
        let event = event.load::<PluginEvent>()?;
        let buf = event
            .params
            .event_data
            .ok_or_else(|| anyhow!("Missing event data"))?;

        let num = u64::from_le_bytes(buf.try_into()?);

        // increase the number of occurrences of `num` in the histogram
        *self.histogram.entry(num).or_insert(0) += 1;

        Ok(())
    }
}

/// Implement the field extraction capability
/// https://falco.org/docs/plugins/architecture/#field-extraction-capability
/// https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/extract/trait.ExtractPlugin.html
///
/// This trait exposes a set of items that need to be satisifed
///
/// # The set of event types supported by this plugin
/// If empty, the plugin will get invoked for all event types, otherwise it will only
/// get invoked for event types from this list.
///
/// # The set of event sources supported by this plugin
/// If empty, the plugin will get invoked for events coming from all sources, otherwise it will
/// only get invoked for events from sources named in this list.
///
/// # The extraction context
/// # The actual list of extractable fields
impl ExtractPlugin for RandomGenPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["random_generator"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("gen.num", &Self::extract_number),
        field("gen.count", &Self::extract_count),
    ];
}

static_plugin!(MY_SOURCE_PLUGIN = RandomGenPlugin);

fn main() {
    // just needed to build the exercise
}

mod tests {
    use exercises::native::NativeTestDriver;
    use exercises::{init_plugin, CapturingTestDriver, TestDriver};
    use falco_plugin::strings::CStringWriter;
    use std::io::Write;

    #[test]
    fn extract_field() {
        let (mut driver, plugin) =
            init_plugin::<NativeTestDriver>(&super::MY_SOURCE_PLUGIN, c"{\"range\": 10}").unwrap();
        let _ = driver.add_filterchecks(&plugin, c"random_generator");

        let mut driver = driver.start_capture(c"", c"").unwrap();

        // Fetch 20 events
        for n in 1..=20 {
            let event = driver.next_event().unwrap();

            if n == 20 {
                // add all the occurrences of all the numbers in the range and make sure
                // the sum equals the number of iterations (20)

                let mut sum = 0;
                for i in 0..10 {
                    let mut field = CStringWriter::default();
                    write!(&mut field, "gen.count[{}]", i).unwrap();
                    let field = field.into_cstring();
                    let num = driver
                        .event_field_as_string(&field, &event)
                        .unwrap()
                        .unwrap();
                    let num = num.parse::<u64>().unwrap();

                    sum += num;
                }

                assert_eq!(sum, 20);
            }
        }
    }
}
