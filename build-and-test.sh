set -e 

# Build the plugin
cargo build

# Copy the plugin to the Wireshark plugin folder
mkdir -p ~/.local/lib/wireshark/plugins/4.4/epan/
cp ../target/debug/libelpis.so ~/.local/lib/wireshark/plugins/4.4/epan/
cp ./messages.json ~/.local/lib/wireshark/plugins/4.4/epan/

echo "Plugin copied to ~/.local/lib/wireshark/plugins/4.4/epan/"

# Parse a sample packet
tshark -r ./tests/test1.pcap -V