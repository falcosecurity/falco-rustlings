use falco_plugin::anyhow::Error;
use falco_plugin::base::Plugin;
use falco_plugin::static_plugin;
use falco_plugin::tables::TablesInput;
use std::ffi::CStr;

//
// INTRO
// The scope of this exercise is to introduce you the `Plugin` trait and the `static_plugin` macro.
//

// This is the type that represents your first plugin. It does not have any fields,
// because we do not need to store any state yet.
struct NoOpPlugin;

// Every plugin needs some basic metadata about itself: name, version etc., as well as
// a way to build itself (a constructor). These are provided by the Plugin trait,
// that you need to implement for each type.
//
// All the string constants you need to provide are C-style strings, so you need
// to use the c"foo" syntax for them.
// See: https://doc.rust-lang.org/edition-guide/rust-2021/c-string-literals.html
//
// As our plugin does not support configuration right now, use the empty tuple () as ConfigType
//
// DOCS: https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/base/trait.Plugin.html
impl Plugin for NoOpPlugin {
    const NAME: &'static CStr = c"noop-plugin";
    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    const DESCRIPTION: &'static CStr = c"The simplest possible plugin";
    const CONTACT: &'static CStr = c"https://github.com/falcosecurity/plugin-sdk-rs";
    type ConfigType = ();

    fn new(input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self, Error> {
        Ok(Self)
    }
}

// When you build actual plugins, you will probably want to build them as shared libraries,
// so that Falco can load them. In these exercises, we will make them into statically linkable
// plugins, as that fits Rustlings better (each exercise is a standalone binary).
//
// Don't worry, we'll see how to build dynamically linked plugins later :)
//
// The `#[no_capabilities]` attribute is to explicitly tell the SDK that we want to build
// a plugin that cannot do anything (because that's all we know how to do for now!).
// Such a plugin will cause an error if you try to load it into Falco, so by default
// the SDK will raise an error if your plugin does not have any capabilities.
//
// DOCS: https://falcosecurity.github.io/plugin-sdk-rs/falco_plugin/macro.static_plugin.html
static_plugin!(#[no_capabilities] NO_OP_PLUGIN = NoOpPlugin);

fn main() {
    // just needed to build the exercise
}
