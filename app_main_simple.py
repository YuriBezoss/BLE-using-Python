#!/usr/bin/env python

"""
Reference: bglib_test_htm_collector.py by jeff rowberg
bglib.py was edited due to errors; errors were commented and edited with the 
ff note: error 10022019 (mm-dd-yyyy) were errors were noted

"""
################################################################################
# IMPORTS
################################################################################
# BLE imports
import bglib, serial, time, signal, binascii
import my_constants

# GUI imports
import tkinter
from tkinter.messagebox import askokcancel
from gui_func_test import *

# other imports
import sys
import os

################################################################################

################################################################################
# GLOBAL VARIABLES
################################################################################
ble = 0
ser = 0
devices_scanned = list()
scan_retry = 0
connection_handle = 0
device_info = dict()



################################################################################

################################################################################
# EVENT HANDLERS
################################################################################
# handler to notify of an API parser timeout condition
def my_timeout(sender, args):
    global txtwin
    # might want to try the following lines to reset, though it probably
    # wouldn't work at this point if it's already timed out:
    #ble.send_command(ser, ble.ble_cmd_system_reset(0))
    #ble.check_activity(ser, 1)
    statwin.write("Status: BGAPI parser timed out. Make sure the BLE device is in a known/idle state.")

# gap_scan_response handler
def my_ble_evt_gap_scan_response(sender, args):
    global ble, ser, devices_scanned, txtwin, statwin
    
    if args['data'] in [i['data'] for i in devices_scanned]:
        if args['sender'] in [i['sender'] for i in devices_scanned]:
            pass
    else:
        # format args: rssi, packet type, sender, address type, bond, packet data
        rssi = args['rssi']
        packet_type = my_constants.packet_type[args['packet_type']]
        sender = "{0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}".format(*[i for i in args['sender'][::-1]])
        # address type
        addr_type = my_constants.address_type[args['address_type']]
        #bond
        bond = hex(args['bond'])
        # packet data: pull all advertised service info from ad packet
        ad_services = dict()
        this_field = []
        bytes_left = 0
        for b in args['data']:
            if bytes_left == 0:
                bytes_left = b
                this_field = []
            else:
                this_field.append(b)
                bytes_left = bytes_left - 1
                if bytes_left == 0:
                    field_type = this_field[0]
                    field_data = this_field[1:]
                    field_name = ''
                    for code,name in my_constants.gap_data_type.items():
                        if field_type == code:
                            field_name = name
                            ad_services[field_name] = bytearray(field_data)
        
        # display args
        txtwin.write("\n---GAP Scan Response---")
        txtwin.write("{0:15s}: {1} dBm".format("RSSI", rssi))
        txtwin.write("{0:15s}: {1}".format("Packet Type", packet_type))
        txtwin.write("{0:15s}: {1}".format("Sender", sender))
        txtwin.write("{0:15s}: {1}".format("Address Type", addr_type))
        txtwin.write("{0:15s}: {1}".format("Bond", bond))
        txtwin.write("Packet Data:")
        for key,value in ad_services.items():
            txtwin.write("    * {0}: {1}".format(key, value))
    
        devices_scanned.append(args)
        

# connection_status handler
def my_ble_evt_connection_status(sender, args):
    global ble, ser, connection_handle, txtwin, statwin
    global device_info
    
    # format args: connection, flags, address, address type, connection interval, timeout, latency, bonding
    # connection handle
    connection_handle = args['connection']
    flags = ''
    if args['flags'] & 0b0001 == 1:
        flags += my_constants.flags_enum[1]
    if args['flags'] & 0b0010 == 2:
        flags += my_constants.flags_enum[2]
    if args['flags'] & 0b0100 == 4:
        flags += my_constants.flags_enum[3]
    if args['flags'] & 0b1000 == 8:
        flags += my_constants.flags_enum[4]
    addr = "{0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}".format(*[i for i in args['address'][::-1]])
    addr_type = my_constants.address_type[args['address_type']]
    conn_interval = args['conn_interval'] * 1.25
    timeout = args['timeout'] * 10
    latency = args['latency'] * conn_interval
    bonding = hex(args['bonding'])
    
    statwin.write("Status: Connected to device {0}".format(addr))
    # display args
    txtwin.write("\n---Connection Status---")
    txtwin.write("{0:15s}: {1}".format("Conn Handle", connection_handle))
    txtwin.write("{0:15s}: {1}".format("Flags", flags))
    txtwin.write("{0:15s}: {1}".format("Address", addr))
    txtwin.write("{0:15s}: {1}".format("Address Type", addr_type))
    txtwin.write("{0:15s}: {1} ms".format("Conn Interval", conn_interval))
    txtwin.write("{0:15s}: {1} ms".format("Timeout", timeout))
    txtwin.write("{0:15s}: {1} ms".format("Latency", latency))
    txtwin.write("{0:15s}: {1}".format("Bonding", bonding))
    
    #enable buttons
    button_start.config(state="disabled", background="green")
    button_scan.config(state="normal")
    button_connect.config(state="disabled")
    button_disconnect.config(state="normal")
 

# disconnection_status handler 
def my_ble_evt_connection_disconnected(sender, args):
    global ble, ser, txtwin, statwin
    # format args: connection, reason
    # connection
    connection = args['connection']
    # reason
    reason = ''
    for err in [my_constants.bgapi_errors, my_constants.bluetooth_errors, my_constants.security_manager_protocol_errors, my_constants.attribute_protocol_erors]:
        for code, name in err.items():
            if args['reason'] == code:
                reason = name
    if reason == '':
        reason = args['reason']
        
    # display args
    txtwin.write("\n---Disconnection Status---")
    txtwin.write("{0:15s}: {1}".format("Connection", connection))
    txtwin.write("{0:15s}: {1}".format("Reason", reason))
    
    
def my_ble_evt_attclient_find_information_found(sender, args):
    global ble, ser, characteristics_info, connection_handle, txtwin, statwin
    
    #format args:
    connection = args['connection']
    chrhandle = args['chrhandle']
    uuid = []
    uuid_name = ''
    uuid_number = 0
    if len(args['uuid']) == 2:
        uuid_int = (args['uuid'][1]<<8)|args['uuid'][0]           # int format
        for gatt in [my_constants.gatt_characteristics, my_constants.gatt_declarations, my_constants.gatt_descriptors, my_constants.gatt_services]:
            for code, name in gatt.items():
                if uuid_int == code:
                    uuid_name = name
                    uuid_number = '0000'+hex(code)[2:]+'-0000-1000-8000-00805F9B34FB'
    else:
        uuid = "".join([format(i, '02X') for i in args['uuid'][::-1]])
        uuid_name = 'Custom UUID'
        uuid_number = "{0}-{1}-{2}-{3}-{4}".format(uuid[0:8],uuid[8:12],uuid[12:16],uuid[16:20],uuid[20:32])
    
    # display args
    txtwin.write("\n---Attclient Information Found---")
    txtwin.write("{0:15s}: {1}".format("Connection", connection))
    txtwin.write("{0:15s}: {1}".format("Chr Handle", chrhandle))
    txtwin.write("{0:15s}: {1}".format("UUID name", uuid_name))
    txtwin.write("{0:15s}: {1}".format("UUID number", uuid_number))
    args['uuid_name'] = uuid_name
    args['uuid_number'] = uuid_number
    characteristics_info.append(args)
        
        
def my_ble_evt_attclient_procedure_completed(sender, args):
    global ble, ser, connection_handle, characteristics_info, txtwin, statwin
    global device_info, mode

    # format args:
    connection = args['connection']
    if args['result'] == 0:
        result = 'Completed'
    else:
        result = my_constants.attribute_protocol_erors[args['result']]
    chrhandle = args['chrhandle']
    
    txtwin.write("\n---Attclient Information Completed---")
    txtwin.write("{0:15s}: {1}".format("Connection", connection))
    txtwin.write("{0:15s}: {1}".format("Result", result))
    txtwin.write("{0:15s}: {1}".format("Chr Handle", chrhandle))

    

def my_ble_evt_attclient_attribute_value(sender, args):
    global ble, ser, connection_handle, txtwin, statwin
    global device_info, mode
    global date_win, tool_win, prod_win
    
    connection = args['connection']
    atthandle = args['atthandle']
    type = my_constants.attribute_value_type[args['type']]
    raw_val = args['value']
    hex_val = [format(i, '02X') for i in args['value']]
    ascii_value = list()
    for field in args['value']:
        ascii_value.append(chr(field))
    ascii_value = ''.join(ascii_value)
    
    txtwin.write("\n---Attclient Attributes Value---")
    txtwin.write("{0:15s}: {1}".format("Connection", connection))
    txtwin.write("{0:15s}: {1}".format("Handle", atthandle))
    txtwin.write("{0:15s}: {1}".format("Type", type))
    txtwin.write("{0:15s}: {1}".format("Value (raw)", raw_val))
    txtwin.write("{0:15s}: {1}".format("Value (hex)", hex_val))
    txtwin.write("{0:15s}: {1}".format("Value (ASCII code)", ascii_value))
    if args['atthandle'] == device_info['Device Name']:
        device_info['Device Name'] = ascii_value
    elif args['atthandle'] == device_info['Appearance']:
        device_info['Appearance'] = ascii_value
    device_info['data'] = ''
    txtwin.write("\n---Device Information---")
    txtwin.write("{0:15s}: {1}".format("Device Name", device_info['Device Name']))
    txtwin.write("{0:15s}: {1}".format("Address", device_info['address']))
    txtwin.write("{0:15s}: {1}".format("Appearance", device_info['Appearance']))


################################################################################

################################################################################
# BLUETOOTH FUNCTIONS
################################################################################
def ble_start(port_num, baud_rate=11520, debug=False):
    global ble, ser, txtwin, statwin
    
    option_port = port_num
    option_baud = baud_rate
    option_packet = False
    option_debug = debug
    
    # create and setup BGLib object
    statwin.write("Status: USB Dongle Initializing...")
    ble = bglib.BGLib()
    ble.packet_mode = option_packet
    ble.debug = option_debug

    # add handler for BGAPI timeout condition (hopefully won't happen)
    ble.on_timeout += my_timeout

    # add handlers for BGAPI events
    ble.ble_evt_gap_scan_response += my_ble_evt_gap_scan_response
    ble.ble_evt_connection_status += my_ble_evt_connection_status
    ble.ble_evt_connection_disconnected += my_ble_evt_connection_disconnected
    # create serial port object
    ser = serial.Serial(port=option_port, baudrate=option_baud, timeout=1, writeTimeout=1)

    # flush buffers
    ser.flushInput()
    ser.flushOutput()
    
    statwin.write("Status: USB Dongle Initialization Completed")
    # disconnect if we are connected already
    statwin.write("Status: Disconnecting...")
    for i in range(9):
        ble.send_command(ser, ble.ble_cmd_connection_disconnect(i))
        ble.check_activity(ser, 1)
    
    #enable buttons
    button_start.config(state="disabled", background="green")
    button_scan.config(state="normal")
    button_connect.config(state="disabled")

def ble_scan():
    global ble, ser, txtwin, statwin
    
    # stop advertising if we are advertising already
    statwin.write("Status: Stopping Advertisment and Scanning...")
    ble.send_command(ser, ble.ble_cmd_gap_set_mode(0, 0))
    ble.check_activity(ser, 1)

    # stop scanning if we are scanning already
    ble.send_command(ser, ble.ble_cmd_gap_end_procedure())
    ble.check_activity(ser, 1)
    # set scan parameters
    statwin.write("Status: Setting scan parameters...")
    ble.send_command(ser, ble.ble_cmd_gap_set_scan_parameters(0xC8, 0xC8, 1))
    ble.check_activity(ser, 1)

    # start scanning now
    statwin.write("Status: Starting scan now...")
    ble.send_command(ser, ble.ble_cmd_gap_discover(1))
    ble.check_activity(ser, 1)
    for i in range(500):
        # check for all incoming data (no timeout, non-blocking)
        ble.check_activity(ser)
        # don't burden the CPU
        time.sleep(0.01)
    statwin.write("Status: Stopping scan now...")
    ble.send_command(ser, ble.ble_cmd_gap_end_procedure())
    ble.check_activity(ser, 1)
    
    #enable buttons
    button_start.config(state="disabled", background="green")
    button_scan.config(state="normal")
    button_connect.config(state="normal")
    button_disconnect.config(state="disabled")
    
    
  
def ble_connect(device_addr):
    global ble, ser, txtwin, statwin
    addr_type = 0
    addr_byte = (binascii.unhexlify(device_addr.replace(":","")))[::-1]
    statwin.write("Status: Connecting to {0}...".format(device_addr))
    ble.send_command(ser, ble.ble_cmd_gap_connect_direct(addr_byte, addr_type, 0x20, 0x30, 0x100, 0))
    for i in range(3000):    # wait around 3 seconds (300x0.01)
        # check for all incoming data (no timeout, non-blocking)
        ble.check_activity(ser)
        # don't burden the CPU
        time.sleep(0.01)


def ble_disconnect(conn_handle):
    global ble, ser, txtwin, statwin
    statwin.write("Status: Disconnecting...")
    ble.send_command(ser, ble.ble_cmd_connection_disconnect(conn_handle))
    for i in range(200):    # wait around 2 seconds (200x0.01)
        # check for all incoming data (no timeout, non-blocking)
        ble.check_activity(ser)
        # don't burden the CPU
        time.sleep(0.01)
    statwin.write("Status: Disconnected")
################################################################################

################################################################################
# MAIN GUI
################################################################################
def main_GUI():
    global ble, ser
    global window
    window = tkinter.Tk()
    window.title("BLE Logger")
    window.rowconfigure(0, weight=1)
    window.columnconfigure(0, weight=2)                 # frame for text display
    window.columnconfigure(1, weight=1)                 # frame for buttons
    makemenu(window)
    
    """frame for the scrolled text window"""            # 1 column; 2 rows
    text_frame = MyFrame(window)                        # for label and scrolledtext
    text_frame.grid(row=0, column=0, sticky="nsew")
    text_frame.columnconfigure(0, weight=1)
    text_frame.rowconfigure(1, weight=1)                # for scrolledtext row
    
    #scrolledtext window
    global txtwin, statwin
    lbl1 = tkinter.Label(text_frame, text="Information Window", font=("courier", 10, "bold"))
    lbl2 = tkinter.Label(text_frame, text="Status Window", font=("courier", 10, "bold"))
    txtwin = MyScrolledText(text_frame, height=15, width=100)
    txtwin.columnconfigure(0, weight=1)
    txtwin.rowconfigure(0, weight=1)
    
    statwin = MyScrolledText(text_frame, height=8, width=100)
    statwin.columnconfigure(0, weight=1)
    statwin.rowconfigure(0, weight=1)
    
    
    lbl1.grid(row=0, column=0, sticky="sw")
    txtwin.grid(row=1, column=0, sticky="nsew")
    lbl2.grid(row=2, column=0, sticky="sw")
    statwin.grid(row=3, column=0, sticky="nsew")
    
    show_ble_functions(window)

def show_ble_functions(window):
    """frame for the ble functions"""                # 2 columns; many rows
    ble_frame = MyFrame(window)
    ble_frame.grid(row=0, column=1,sticky="nsew")
    ble_frame.columnconfigure(0, weight=1)           # column for buttons
    ble_frame.columnconfigure(1, weight=1)           # column for entry
    
    #ble buttons
    global button_start, button_scan, button_connect, button_disconnect
    global connection_handle
    
    button_start = MyButton(ble_frame, text="Initialize USB Dongle", command=(lambda: ble_start(entry_com_port.get())))
    button_start.config(state="normal")
    button_scan = MyButton(ble_frame, text="Scan for Devices", command=(lambda: ble_scan()))
    button_connect = MyButton(ble_frame, text="Connect", command=(lambda: ble_connect(entry_address.get())))
    button_disconnect = MyButton(ble_frame, text="Disconnect", command=(lambda: ble_disconnect(connection_handle)))
    
 
    
    tkinter.Label(ble_frame, text="BLE Function", font=("courier", 10, "bold")).grid(row=0, columnspan=2, sticky="nsew")
    button_start.grid(row=1, column=0, sticky="nsew")
    button_scan.grid(row=2, column=0, sticky="nsew")
    button_connect.grid(row=3, column=0, sticky="nsew")
    button_disconnect.grid(row=4, column=0, sticky="nsew")

    

    
    #ble entry
    global entry_com_port, entry_address
    
    entry_com_port = MyEntry(ble_frame)
    entry_com_port.insert(0, 'COM6')
    entry_address = MyEntry(ble_frame)
    entry_address.insert(0, '<Device Address>')

    
    entry_com_port.grid(row=1, column=1, sticky="nsew")
    entry_address.grid(row=3, column=1, sticky="nsew")
    
    window.mainloop()
    

def makemenu(win):
    top = tkinter.Menu(win)
    win.config(menu=top)
    file = tkinter.Menu(top)
    file.add_command(label='Show Bluetooth Functions', command=(lambda: show_ble_functions(window)), underline=0)
    file.add_command(label='Clear Info Window', command=(lambda: txtwin.clear()), underline=0)
    file.add_command(label='Clear Status Window', command=(lambda: statwin.clear()), underline=0)
    file.add_command(label='Quit', command=(lambda: close_window(window)), underline=0)
    top.add_cascade(label='Menu', menu=file, underline=0)
    

def close_window(window):
    try:
        adapter.stop()
    except NameError:
        pass
    except:
        statwin.write("Error occurred during insertion of data into the table.")
        statwin.write("Error info: {0} => {1}".format(sys.exc_info()[0], sys.exc_info()[1]))
    else:
        statwin.write("Status: Stoppping USB Dongle...")
    finally:
        ans = askokcancel('Verify exit', 'Really quit?')
        if ans: window.destroy()
    
################################################################################



################################################################################
# MAIN FUNCTIONS
################################################################################
# gracefully exit without a big exception message if possible
def ctrl_c_handler(signal, frame):
    print('Goodbye!')
    exit(0)

signal.signal(signal.SIGINT, ctrl_c_handler)

if __name__ == '__main__':

    main_GUI()

    
################################################################################

