use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::event::events::types::{
    PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X, PPME_SYSCALL_OPEN_X, PPME_SYSCALL_READ_E,
    PPME_SYSCALL_READ_X,
};
use falco_plugin::event::events::{Event, EventMetadata, EventToBytes, PayloadToBytes};
use falco_plugin::event::fields::types::{PT_FLAGS32_file_flags, PT_ERRNO, PT_FD, PT_FSPATH};
use falco_plugin::extract::EventInput;
use falco_plugin::source::{EventBatch, SourcePlugin, SourcePluginInstance};
use falco_plugin::strings::CStringWriter;
use falco_plugin::tables::TablesInput;
use falco_plugin::{static_plugin, FailureReason};
use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::io::Write;

struct SyscallSourcePlugin(VecDeque<Vec<u8>>);

fn event_to_bytes<T: PayloadToBytes>(payload: T) -> Vec<u8> {
    let evt = Event {
        metadata: EventMetadata { ts: 1, tid: 1 },
        params: payload,
    };

    let mut buf = Vec::new();
    evt.write(&mut buf).unwrap();
    buf
}

fn build_syscall_events() -> VecDeque<Vec<u8>> {
    let mut evts = VecDeque::new();

    evts.push_back(event_to_bytes(PPME_SYSCALL_OPEN_X {
        fd: Some(PT_FD(5)),
        name: Some(PT_FSPATH::new("/etc/passwd")),
        flags: Some(PT_FLAGS32_file_flags::O_RDWR),
        mode: Some(0o644),
        dev: Some(0),
        ino: Some(0),
    }));

    evts.push_back(event_to_bytes(PPME_SYSCALL_READ_E {
        fd: Some(PT_FD(5)),
        size: Some(5),
    }));

    evts.push_back(event_to_bytes(PPME_SYSCALL_READ_X {
        res: Some(PT_ERRNO(5)),
        data: Some(b"hello"),
    }));

    evts.push_back(event_to_bytes(PPME_SYSCALL_CLOSE_E { fd: Some(PT_FD(5)) }));

    evts.push_back(event_to_bytes(PPME_SYSCALL_CLOSE_X {
        res: Some(PT_ERRNO(0)),
    }));

    evts
}

// Metadata for our plugin, you know the drill :)
impl Plugin for SyscallSourcePlugin {
    const NAME: &'static CStr = c"syscall";
    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    const DESCRIPTION: &'static CStr = c"Dummy syscall source plugin.";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/plugin-sdk-rs";
    type ConfigType = ();

    fn new(_input: Option<&TablesInput>, _config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self(build_syscall_events()))
    }
}

impl SourcePlugin for SyscallSourcePlugin {
    type Instance = SyscallSourcePluginInstance;
    const EVENT_SOURCE: &'static CStr = c"syscall";
    const PLUGIN_ID: u32 = 0;

    fn open(&mut self, _params: Option<&str>) -> Result<Self::Instance, Error> {
        Ok(SyscallSourcePluginInstance(self.0.clone()))
    }

    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
        let event = event.event()?;
        let event = event.load_any()?;
        let mut writer = CStringWriter::default();
        write!(&mut writer, "{:?}", event)?;

        Ok(writer.into_cstring())
    }
}

struct SyscallSourcePluginInstance(VecDeque<Vec<u8>>);

impl SourcePluginInstance for SyscallSourcePluginInstance {
    type Plugin = SyscallSourcePlugin;

    fn next_batch(
        &mut self,
        _plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        match self.0.pop_front() {
            Some(event) => {
                batch.add(&*event)?;
                Ok(())
            }
            None => Err(FailureReason::Eof)?,
        }
    }
}

static_plugin!(SYSCALL_SOURCE_PLUGIN = SyscallSourcePlugin);

pub static PLUGIN: falco_plugin::api::plugin_api = SYSCALL_SOURCE_PLUGIN;
