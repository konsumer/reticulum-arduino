This is a basic & simple Arduino library for [reticulum](https://reticulum.network/). It does not do any transport-stuff (you can use whatever you like) it just manages identities and helps with packets.

You will need to install these llibraries in the ArduinoIDE Library tab:

- Crypto by Rhys Weatherley

It should just compile in ArduinoIDE, normally, once you put this project dir into your ~/Arduino/libraries dir. You can find some examples under File/Examples/reticulum-arduino.


If you prefer the command-line (like I do) you can use [arduino-cli](https://arduino.github.io/arduino-cli):

```sh
# install arduino-cli in ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | BINDIR=~/.local/bin sh

# default config
arduino-cli config init

# install Crypto lib
arduino-cli lib install Crypto

# add your board-definitions, this is for all supported ESP32s
arduino-cli config set board_manager.additional_urls "https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json"
arduino-cli core update-index
arduino-cli core install esp32:esp32

# get a list of ESP32 board names, grep is to filter name, I chose "Heltec WiFi Kit 32(V3)"
arduino-cli board listall esp32:esp32 | grep Heltec
ARDUINO_BOARD="esp32:esp32:heltec_wifi_kit_32_V3"

# list USB devices, I chose the USB port my device is on
arduino-cli board list
ARDUINO_DEVICE=/dev/ttyUSB1

# compile "offline" example
arduino-cli compile --fqbn "${ARDUINO_BOARD}" $(pwd)/examples/offline

# upload "offline" example
arduino-cli upload -p "${ARDUINO_DEVICE}" --fqbn "${ARDUINO_BOARD}" $(pwd)/examples/offline

# monitor serial (Ctrl-C to exit)
arduino-cli monitor -p "${ARDUINO_DEVICE}" --config 115200
```
