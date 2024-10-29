// Implements an ELPIS packet parser for Wireshark

use anyhow::Context;
use bitstream_io::ByteRead;
use elpis::{ElpisMessages, MessageDefinition};
use epan_sys::*;
use lazy_static::lazy_static;
use plugshark::*;
use std::{
    cell::RefCell,
    collections::HashSet,
    ffi::*,
    fs,
    io::{self, BufRead},
    path::PathBuf,
    rc::Rc,
    sync::Mutex,
};
mod elpis;

// Defines a C string in a constant form that's easier to use in Rust.
macro_rules! cstr {
    ($s:expr) => {
        concat!($s, "\0").as_ptr() as *const c_char
    };
}

// Plugin version string
#[no_mangle]
#[used]
pub static plugin_version: &'static CStr = unsafe { CStr::from_ptr(cstr!("1.0.0")) };

// Major version of Wireshark that the plugin is built for
#[no_mangle]
#[used]
pub static plugin_want_major: c_int = 4;

// Minor version of Wireshark that the plugin is built for
#[no_mangle]
#[used]
pub static plugin_want_minor: c_int = 4;

// Load all ELPIS messages from the messages.json file on startup
lazy_static! {
    static ref ELPIS_MESSAGES: Mutex<ElpisMessages> = Mutex::new(decode_elpis_packets_from_json());
}

// Decodes all ELPIS messages from the messages.json file
fn decode_elpis_packets_from_json() -> ElpisMessages {
    // Get the path to where this dynamic library is located
    let plugin_path = find_library_path("libelpis.so").unwrap().unwrap();
    let plugin_path = PathBuf::from(plugin_path).parent().unwrap().to_path_buf();

    // Build a path to a messages.json file in the same directory as the module
    let json_path = plugin_path.join("messages.json");

    // Load the ELPIS messages from the JSON file
    ElpisMessages::load_from_json(json_path.to_str().unwrap()).unwrap()
}

// Locates the path to the plugin's dynamic library
fn find_library_path(library_name: &str) -> io::Result<Option<String>> {
    let file = fs::File::open("/proc/self/maps")?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.contains(library_name) {
            // Assume the path is the last part of the line
            if let Some(pos) = line.find('/') {
                return Ok(Some(line[pos..].to_string()));
            }
        }
    }

    Ok(None)
}

// Entrypoint of the plugin, registers the plugin, its protocols, and all field type definitions.
#[no_mangle]
pub unsafe extern "C" fn plugin_register() {
    WiresharkPlugin::setup(|mut plugin| {
        let mut protocol =
            WiresharkProtocolDefinition::new(dissect_callback, "ELPIS Packet", "elpis", "elpis");

        // The packet ID of the packet
        protocol.add_field_type(
            WiresharkFieldArgs::new("elpis.id", "Id")
                .with_field_type(FieldType::Uint8)
                .with_display(FieldDisplayType::BaseHex),
        );

        // Length of the packet
        protocol.add_field_type(
            WiresharkFieldArgs::new("elpis.len", "Length")
                .with_field_type(FieldType::Uint8)
                .with_display(FieldDisplayType::BaseHex),
        );

        // The name of the packet
        protocol.add_field_type(
            WiresharkFieldArgs::new("elpis.name", "Name")
                .with_field_type(FieldType::String)
                .with_display(FieldDisplayType::BaseNone),
        );

        // Generic payload bytes
        protocol.add_field_type(
            WiresharkFieldArgs::new("elpis.payload", "Payload")
                .with_field_type(FieldType::Bytes)
                .with_display(FieldDisplayType::BaseNone),
        );

        // The formatted signal string from a packet
        protocol.add_field_type(
            WiresharkFieldArgs::new("elpis.signal_formatted", "Signal")
                .with_field_type(FieldType::None)
                .with_display(FieldDisplayType::BaseNone),
        );

        // The name of a signal decoded from the packet, for searching for a packet with a specific signal in it
        protocol.add_field_type(
            WiresharkFieldArgs::new("elpis.signal_name", "Name")
                .with_field_type(FieldType::String)
                .with_display(FieldDisplayType::BaseNone),
        );

        // The value of a signal decoded from the packet, for searching for a specific signal with a specific value
        // Example: elpis.signal_kv == "ESP_WSpeed_Front_Message_Counter=2"
        protocol.add_field_type(
            WiresharkFieldArgs::new("elpis.signal_kv", "Name=Value")
                .with_field_type(FieldType::String)
                .with_display(FieldDisplayType::BaseNone),
        );

        // Packet placeholder field
        protocol.add_field_type(WiresharkFieldArgs::new("elpis.frame", "ELPIS Frame"));

        // ELPIS is sent over port 20000
        protocol.add_match_condition("udp.port", WiresharkMatchType::UInt32(20000));

        // Set the number of ETT fields for this protocol
        // Allow a maximum of 64 frames to be opened and closed this way
        // Also allow up to 256 signals to be expanded this way
        protocol.set_num_ett(2 + 64 + 256);

        plugin.add_protocol(protocol);
    });
}

unsafe fn parse_elpis_payload(
    tree: &mut DissectorSubTree,
    definition: &MessageDefinition,
    payload_length: i32,
    signal_field_handle: c_int,
    elpis_signal_name_handle: c_int,
    elpis_signal_formatted_handle: c_int
) -> anyhow::Result<()> {
    let payload = tree.get_slice_here(payload_length);

    let mut current_signal_idx = 0;
    for signal in definition.signals.iter() {
        let is_big_endian = signal.is_big_endian;
        let signal_start: i32;

        // Choose the proper starting index when no index is given
        if is_big_endian {
            signal_start = signal.start.unwrap_or(7);
        } else {
            signal_start = signal.start.unwrap_or(0);
        }

        let signal_name = signal.name.as_str();
        let signal_length = signal.length;

        // If the signal is present, but the length is zero, skip it
        if signal_length == 0 {
            continue;
        }

        let data: u128;
        // Read the value as a u64, for sizes that exceed the size of a u64, ignore it for now.
        if (signal_length / 8) >= 16 {
            println!("WARN: Signal {} is too large to fit in a u128", signal_name);
        } else {
            let byte_offset = signal_start / 8;
            let byte_length = (signal_length + 7) / 8;

            // Read the signal value from the buffer given the parameters
            data = if is_big_endian {
                elpis::read_bits_motorola_be(payload, signal_start, signal_length)
                    .with_context(|| format!("Could not read signal {}", signal_name))?
            } else {
                elpis::read_bits_intel_le(payload, signal_start, signal_length)
                    .with_context(|| format!("Could not read signal {}", signal_name))?
            };

            let mut subtree = tree.push_subtree_generated(elpis_signal_formatted_handle, IndexPosition::Current(0), byte_length, 1 + 64 + current_signal_idx);
            current_signal_idx += 1;
            if current_signal_idx > 255 {
                current_signal_idx = 255;
            }

            subtree.get_top_item().set_text(format!("{}: {} ({:#x})", signal_name, data, data).as_str());

            let mut val = subtree.add_field_string_value(
                signal_field_handle,
                IndexPosition::Current(byte_offset),
                byte_length,
                format!("{}={}", signal_name, data).as_str(),
            );
            val.set_generated();
            val.set_hidden();

            let mut val = subtree.add_field_string_value(
                elpis_signal_name_handle,
                IndexPosition::Current(byte_offset),
                byte_length,
                signal_name,
            );
            val.set_generated();
        }
    }

    Ok(())
}

// Callback for dissection, called when a packet for this protocol is detected and dissected.
unsafe fn dissect_callback(mut tree: DissectorSubTree) {
    let elpis_name = tree.get_field_handle("elpis.name");
    let elpis_signal_kv_handle = tree.get_field_handle("elpis.signal_kv");
    let elpis_signal_name_handle = tree.get_field_handle("elpis.signal_name");
    let elpis_signal_formatted_handle = tree.get_field_handle("elpis.signal_formatted");
    let elpis_frame = tree.get_field_handle("elpis.frame");

    let result = || -> anyhow::Result<()> {
        // Create a set of all ELPIS strings encountered in this packet
        let mut elpis_strings: HashSet<String> = HashSet::new();

        // Keep current frame idx for ETT indexes.
        // This makes it so that if a frame is opened, that same index will remain open
        // on subsequent packets being displayed.
        let mut current_frame_idx = 0;
        loop {
            let mut buffer = tree.get_buffer_here(TvBuffByteOrder::BigEndian);

            if buffer.remaining() == 0 {
                // Set the column info to the packets we've seen in the hashset
                let mut info_col = elpis_strings
                    .iter()
                    .map(|x| x.as_str())
                    .collect::<Vec<&str>>();
                info_col.sort_by(|a, b| b.cmp(a));
                tree.set_info_column(info_col.join(" / ").as_str());

                break;
            }

            let packet_id = buffer.read::<i32>()?;
            let payload_length = buffer.read::<i32>()?;

            // Check the length of the packet is valid
            let remaining_size: i32 = buffer.remaining().try_into()?;
            if payload_length < 0 || payload_length > remaining_size {
                return Err(anyhow::anyhow!("Invalid payload length"));
            }

            if packet_id < 0 {
                return Err(anyhow::anyhow!("Invalid packet ID"));
            }

            // Pushing a single field into the dissector
            let mut subtree = tree.push_subtree(elpis_frame, IndexPosition::Current(0), payload_length + 8, 1 + current_frame_idx);
            current_frame_idx += 1;
            if current_frame_idx > 63 {
                current_frame_idx = 63;
            }

            // Find the message definition for this packet
            let lock = ELPIS_MESSAGES.lock().unwrap();

            // Locate the message definition for this packet by its id
            let message_def = lock.get_def_by_id(packet_id);

            subtree.add_field(
                "elpis.id",
                IndexPosition::Current(0),
                4,
                FieldEncoding::BigEndian,
            );

            // If we found a message definition, add the name of the packet to the Frame item
            if let Some(message_def) = message_def {
                // Keep track of all names seen in this packet
                elpis_strings.insert(message_def.name.clone());

                // Add the name of the packet to the Frame item
                let mut item = subtree.add_field_string_value(
                    elpis_name,
                    IndexPosition::Current(0),
                    0,
                    message_def.name.as_str(),
                );
                item.set_generated();

                // Append the name to the top level frame
                subtree
                    .get_top_item()
                    .append_text(format!(" ({})", message_def.name).as_str());
            }

            subtree.add_field(
                "elpis.len",
                IndexPosition::Current(0),
                4,
                FieldEncoding::BigEndian,
            );
            if let Some(message_def) = message_def {
                if let Err(x) = parse_elpis_payload(
                    &mut subtree,
                    message_def,
                    payload_length,
                    elpis_signal_kv_handle,
                    elpis_signal_name_handle,
                    elpis_signal_formatted_handle
                ) {
                    panic!("Error parsing ELPIS payload {}: {}", message_def.name, x);
                }
            }
            subtree.add_field(
                "elpis.payload",
                IndexPosition::Current(0),
                payload_length,
                FieldEncoding::LittleEndian,
            );
        }

        Ok(())
    }();

    if let Err(e) = result {
        eprintln!("Error parsing ELPIS packet: {}", e);
    }
}
