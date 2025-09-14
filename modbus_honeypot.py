#!/usr/bin/env python3
import os, datetime
from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import (
    ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock
)
from pymodbus.device import ModbusDeviceIdentification

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGFILE = os.path.join(BASE_DIR, "ampdefend.log")

def log_event(msg):
    print(msg)
    with open(LOGFILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {msg}\n")

class LoggingSlaveContext(ModbusSlaveContext):
    # Log reads/writes so attacks show up in ampdefend.log
    def getValues(self, fx, address, count=1):
        log_event(f"Modbus Read fc={fx} addr={address} count={count}")
        return super().getValues(fx, address, count)
    def setValues(self, fx, address, values):
        log_event(f"Modbus Write fc={fx} addr={address} values={list(values)[:10]}")
        return super().setValues(fx, address, values)

def fake_modbus_server():
    store = LoggingSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),
        co=ModbusSequentialDataBlock(0, [0]*100),
        hr=ModbusSequentialDataBlock(0, [123,456,789] + [0]*97),
        ir=ModbusSequentialDataBlock(0, [0]*100),
        zero_mode=True
    )
    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = 'AMPDefend'
    identity.ProductCode = 'SM'
    identity.ProductName = 'SmartMeter Honeypot'
    identity.ModelName = 'AMPDefend-SM'
    identity.MajorMinorRevision = '1.0'

    log_event("Fake Smart Meter Honeypot listening on port 502...")
    # NOTE: 502 needs root. Run the manager as root (systemd) or change to 1502 for user mode.
    StartTcpServer(context, identity=identity, address=("0.0.0.0", 502))

if __name__ == "__main__":
    fake_modbus_server()

