## Mac layer for the RFM69 radio used with PI PICO

This is a Medium Access control layer for the PI PICO PHY layer using the RFM69 radio.  
This layer defines and manages connections, higher layer packets, packet acknowlagement and packet response timeouts.

It uses the a TDD based phy layer for the the RFM69 radio specifically built for the PI PICO. https://github.com/Helienzo/pi_pico_radio_phy.
  
To test this module check out the examples.  
Note that the examples pulls in a couple of submodules using CMAKE FetchContent. Check the the examples/example/CMakeLists.txt, for source repos.  
  
## Connect the RFM69 chip to Pi Pico As follows:
  
PICO 16 - MISO  
PICO 17 - NSS  
PICO 18 - SCK  
PICO 19 - MOSI  
PICO 20 - RESET  
PICO 21 - DIO0  
  
## Documentation
The macRadio module supports three modes of operation.  
Central  
Peripheral  
Automatic role mode where it alternates between central and peripheral mode searching for a peer to connect to.

The central mode accept incomming connect requests from peripheral devices, confirming by sending acknowlagement. The central device considers a connect request to be a successful connection.

The peripheral device searches for central devices, once a central device is found the peripheral devices sends a connect request and waits for an ackonwlagement. Once the acknowlagement is received the connection is considered successfull.

Once a connection is established the central device keeps sending sync messages and the peripheral device responds with a keep alive confirm message.

If either the peripheral device or the central device fails to detect keep alive messages or sync messages the connection is lost.

Once a connection is established it is possible to send three types of data messages between the devices:
- Stream Packets
- Reliable packets
- Broadcast packets

### Stream packets
A stream packet is sent to a target device with a specific address and only a device with an active connection will receive the message. The message is not confirmed and the sender does not know if it was successfully received by the receiver or not.

### Reliable packets
Reliable packets are sent to a target device with a specific address and only a device with an active connection will receive the message. The reliable messages expects an acknowlagement. A receiving device will send a confirm message if it successfully receives a reliable message. If a reliable message does not receive a acknowlagement the message times out and a message fail will be triggerd.

### Broadcast packets
Broadcast packets are similar to stream packets but any device can receive them.

## Known limitations
 The TDD mode currently only supports two devices in a point to point communication mode.  
 The send function in TDD mode currently does not warn if the packet(a) is longer than the slot time.  
 There might be issues when trying to send close to max throughput, Im working on that..
