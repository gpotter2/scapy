/*
 * Yes, this is NodeJS code within a python project.
 * That's because Python support for Bluetooth is total garbage,
 * and no library are maintained on Python.
 *
 * We'll use bluetooth-hci-socket because they know what they're
 * doing. Here is a client used to communicate with Python...
 *
 */

try {
    const BluetoothHciSocket = require('bluetooth-hci-socket');
} catch {
    console.log("Please `npm i bluetooth-hci-socket`");
    process.exit(1);
}

var standard_input = process.stdin;
standard_input.setEncoding('utf-8');

var getDevices = function(){
    BluetoothHciSocket = new UsbBluetoothHciSocket();
    var usbDevices = usbBluetoothHciSocket.getDeviceList();
    return JSON.stringify(usbDevices);
}

var client = function(socket){
    bluetoothHciSocket.on('data', function(data) {
        console.log(data.toString('hex') + "\r\n");
    });
    standard_input.on('data', function (data) {
        socket.write(Buffer.from(data, 'hex'));
    });
}

var openRawSocket = function(deviceID){
    var bluetoothHciSocket = new BluetoothHciSocket();
    bluetoothHciSocket.bindRaw(deviceID);
}

var args = process.argv.slice(2);
switch (args[0]) {
    case 'devices':
        // get devices
        console.log(getDevices());
        break;
    case 'rawsocket':
        var deviceID = parseInt(args[1]);
        // open socket
        client(openRawSocket(deviceID));
        break;
    default:
        console.log("Unknown argument");
}
