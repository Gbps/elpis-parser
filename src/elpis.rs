use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::{Cursor, SeekFrom}};
use bitstream_io::{BigEndian, BitRead, BitReader, LittleEndian};

fn default_as_true() -> bool {
    true
}

fn default_as_max_f64() -> f64 {
    f64::MAX
}

// Defines all signals in a message. This can use *either* Intel or Motorola endianness
//
#[derive(Serialize, Deserialize, Debug)]
pub struct SignalDefinition {
    pub name: String,
    pub start: Option<i32>,
    pub length: i32,

    #[serde(default = "default_as_true")]
    pub is_big_endian: bool,

    pub default: Option<String>,

    #[serde(default)]
    pub minimum: f64,

    #[serde(default = "default_as_max_f64")]
    pub maximum: f64,

    #[serde(default)]
    pub offset: f64,

    pub multiplexer_signal: Option<String>,
    pub spn: Option<String>,
    pub choices: Option<HashMap<String, i32>>,
    pub  scale: Option<f64>,
    pub unit: Option<String>,
    pub comment: Option<String>,
    pub is_signed: Option<bool>,
    pub is_multiplexer: Option<bool>,
    pub is_float: Option<bool>,
    pub multiplexer_ids: Option<serde_json::Value>, // Can be any type
}

// Defines a top level message definition, and underneath that are all the signals
// and their definitions.
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageDefinition {
    pub name: String,
    pub  length: i32,
    pub id: i32,
    pub comment: Option<String>,
    pub signals: Vec<SignalDefinition>,
}

pub struct ElpisMessages {
    // All message definitions as loaded from the JSON file\
    // Key is the message ID
    // Value is the message definition
    messages: HashMap<i32, MessageDefinition>,
}

impl ElpisMessages {
    // Load ELPIS messages from the given path to a messages.json file
    pub fn load_from_json(json_path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(json_path)
            .with_context(|| format!("Could not open file {}", json_path))?;
        let jsondec: Vec<MessageDefinition> = serde_json::from_str(&contents)
            .with_context(|| format!("Could not parse JSON file {}", json_path))?;

        // Build a hashmap of message IDs to message definitions
        let messages_map: HashMap<i32, MessageDefinition> = jsondec
            .into_iter()
            .map(|message| (message.id, message))
            .collect();

        Ok(Self {
            messages: messages_map,
        })
    }

    // Get the number of messages defined in this decoder
    pub fn get_messagedef_count(&self) -> usize {
        self.messages.len()
    }

    // Find a message definition by its id
    pub fn get_def_by_id(&self, id: i32) -> Option<&MessageDefinition> {
        self.messages.get(&id)
    }

}

// Reads bits from a CAN buffer in Motorola Big Endian order
pub fn read_bits_motorola_be(data: &[u8], start: i32, length: i32) -> anyhow::Result<u128> {
    let start = start as usize;
    let length = length as usize;

    // Motorola bit encoding starts the first bit in the stream at bit index 7 down to 0 in the byte.

    // Select the byte, then convert the bits to a bit slice index.
    let byte_select = start / 8;
    let bit_select = start % 8;
    let adjusted_bit_select = 7 - bit_select;
    let slice_start = byte_select * 8 + adjusted_bit_select;

    let cursor: Cursor<_> = Cursor::new(data);
    let mut reader = BitReader::endian(cursor, BigEndian);
    reader.seek_bits(SeekFrom::Start(slice_start as u64)).with_context(|| format!("Could not seek to position {}", start))?;
    reader.read::<u128>(length as u32).with_context(|| format!("Could not read {} bits from position {}", length, start))
}

// Reads bits from a CAN buffer in Intel Little Endian order
pub fn read_bits_intel_le(data: &[u8], start: i32, length: i32) -> anyhow::Result<u128> {
    let start = start as i64;
    let length = length as i64;

    let cursor: Cursor<_> = Cursor::new(data);
    let mut reader = BitReader::endian(cursor, LittleEndian);
    if (length + start) > ((data.len() as i64) * 8) {
        return Err(anyhow::anyhow!("Cannot read {} bits from position {}", length, start));
    }

    reader.seek_bits(SeekFrom::Start(start as u64)).with_context(|| format!("Could not seek to position {}", start))?;
    reader.read::<u128>(length as u32).with_context(|| format!("Could not read {} bits from position {}", length, start))
}

#[test]
fn read_big_endian_data() {
    // Example buffer
    // 0x12 0x34 0x56 0x78
    let data = vec![0b0001_0010, 0b0011_0100, 0b0101_0110, 0b0111_1000, 0b0001_0010, 0b0011_0100, 0b0101_0110, 0b0111_1000];
    let cursor = Cursor::new(data.clone());

    // Create a BitReader for Big Endian
    let mut reader = BitReader::endian(cursor, BigEndian);

    // Read 16 bits (2 bytes) in big-endian order
    let value: u16 = reader.read(16).unwrap();
    assert_eq!(value, 0x1234);

    // Read another 16 bits
    let next_value: u16 = reader.read(16).unwrap();
    // assert_eq!(next_value, 0x5678);

    // // Now read some of the data in terms of Motorola byte order
    // assert_eq!(read_bits_motorola_be(&data, 7, 8), 0x12);
    // assert_eq!(read_bits_motorola_be(&data, 7, 16), 0x1234);
    // assert_eq!(read_bits_motorola_be(&data, 11, 4), 0x4);
    // assert_eq!(read_bits_motorola_be(&data, 5, 21), 0x91A2B);

    // assert_eq!(read_bits_intel_le(&data, 44, 10), 0x345);
    // assert_eq!(read_bits_intel_le(&data, 38, 20), 0x8D159);
    // assert_eq!(read_bits_intel_le(&data, 10, 45), 0xD159E048D15);
    // assert_eq!(read_bits_intel_le(&data, 0, 54), 0x34567812345678);

}