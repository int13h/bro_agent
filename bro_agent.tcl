#!/bin/sh
# Run tcl from users PATH \
exec tclsh "$0" "$@"

# Bro agent for Sguil - Based on "example_agent.tcl"
# Portions Copyright (C) 2013 Paul Halliday <paul.halliday@gmail.com>
#
#
# Copyright (C) 2002-2008 Robert (Bamm) Visscher <bamm@sguil.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# Make sure you define the version this agent will work with. 
set VERSION "SGUIL-0.8.0"

# Define the agent type here. It will be used to register the agent with sguild.
# The template also prepends the agent type in all caps to all event messages.
set AGENT_TYPE "bro"

# The generator ID is a unique id for a generic agent.
# If you don't use 10001, then you will not be able to
# display detail in the client.
set GEN_ID 10001

# Used internally, you shouldn't need to edit these.
set CONNECTED 0

proc DisplayUsage { cmdName } {

    puts "Usage: $cmdName \[-D\] \[-o\] \[-c <config filename>\] \[-f <bro notice.log>\]"
    puts "  -c <filename>: PATH to config (bro_agent.conf) file."
    puts "  -f <filename>: PATH to bro notice.log."
    puts "  -D Runs sensor_agent in daemon mode."
    exit

}

# bgerror: This is a generic error catching proc. You shouldn't need to change it.
proc bgerror { errorMsg } {

    global errorInfo sguildSocketID

    # Catch SSL errors, close the channel, and reconnect.
    # else write the error and exit.
    if { [regexp {^SSL channel "(.*)":} $errorMsg match socketID] } {

        catch { close $sguildSocketID } tmpError
        ConnectToSguilServer

    } else {

        puts "Error: $errorMsg"
        if { [info exists errorInfo] } {
            puts $errorInfo
        }
        exit

    }

}

# InitAgent: Use this proc to initialize your specific agent.
# Open a file to monitor or even a socket to receive data from.
proc InitAgent {} {

    global DEBUG FILENAME

    if { ![info exists FILENAME] } { 
        # Default file is /usr/local/bro/logs/current/notice.log
        set FILENAME /usr/local/bro/logs/current/notice.log
    }
    if { ![file readable $FILENAME] } {
        puts "Error: Unable to read $FILENAME"
        exit 1
    }
    
    if [catch {open "| tail -F -n 0 -f $FILENAME" r} fileID] {
        puts "Error opening $FILENAME : $fileID"
        exit 1
    }

    fconfigure $fileID -buffering line
    # Proc ReadFile will be called as new lines are appended.
    fileevent $fileID readable [list ReadFile $fileID]

}

#
# ReadFile: Read and process each new line.
#
proc ReadFile { fileID } {

    if { [eof $fileID] || [catch {gets $fileID line} tmpError] } {
    
        puts "Error processing file."
        if { [info exits tmpError] } { puts "$tmpError" }
        catch {close $fileID} 
        exit 1

    } else {
            
        # I prefer to process the data in a different proc.
        ProcessData $line

    }

}

#
# FourSix: Check IP version
#
proc FourSix { ip_port } {

    # Until sguil supports ipv6 we just return 0.0.0.0 for v6 addresses

    # v4
    if { [regexp -expanded {

            ^(\d+\.\d+\.\d+\.\d+):      # ip
            (.*$)                       # port

                } $ip_port match ip port ] } {

        return "$ip|$port"
    }

    # v6
    if { [regexp -expanded {

            ^([0-9A-f]{4}:[0-9A-f]{4}:[0-9A-f]{4}:[0-9A-f]{4}:[0-9A-f]{4}:[0-9A-f]{4}:[0-9A-f]{4}:[0-9A-f]{4}): # ip
            (.*$)                                                                                               # port

                } $ip_port match ip port ] } {

        return "0.0.0.0|$port"

    }

    return "0.0.0.0|0"

}

#
# ProcessData: Here we actually process the line
#
proc ProcessData { line } {

    global HOSTNAME AGENT_ID NEXT_EVENT_ID AGENT_TYPE GEN_ID
    global EVENT_PRIORITY EVENT_CLASS
    global sguildSocketID DEBUG
    set GO 0

    # ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,note,msg,sub,src,dst,p,n,peer_descr,actions,policy_items \
    # suppress_for,dropped,remote_location.country_code,remote_location.region,remote_location.city,remote_location.latitude \
    # remote_location.longitude,metric_index.host,metric_index.str,metric_index.network
    # time,string,addr,port,addr,port,enum,enum,string,string,addr,addr,port,count,string,table[enum],table[count] \
    # interval,bool,string,string,string,double \
    # double,addr,string,subnet

    set fields [split $line '\t']
    if { [llength $fields] == 27 } {

        lassign $fields \
                timestamp uid _src_ip _src_port _dst_ip _dst_port proto note msg sub src dst p n peer_descr actions policy_items \
                suppress_for dropped country_code region city latitude longitude mi_host mi_str mi_network

        if { [regexp -expanded {

            ^(\d{10}).      # seconds
            (\d{6})$        # ms

                } $timestamp match seconds ms ] } {

            # Format timestamp
            set nDate [clock format $seconds -gmt true -format "%Y-%m-%d %T"]

            # Source address and port
            if { $_src_ip == "-" } {
                set parts [split [FourSix "$src:0"] "|"]
            } else {
                set parts [split [FourSix "$_src_ip:$_src_port"] "|"]
            }

            lassign $parts src_ip src_port

            # Destination address and port
            if { $_dst_ip == "-" } {
                set parts [split [FourSix "$dst:$p"] "|"]
            } else {
                set parts [split [FourSix "$_dst_ip:$_dst_port"] "|"]
            }

            lassign $parts dst_ip dst_port

            if { $DEBUG } {
                puts "\n----"
                puts "ts: $timestamp"
                puts "uid: $uid"
                puts "id.orig_h: $src_ip"
                puts "id.orig_p: $src_port"
                puts "id.resp_h: $dst_ip"
                puts "id.resp_p: $dst_port"
                puts "proto: $proto"
                puts "note: $note"
                puts "msg: $msg"
                puts "sub: $sub"
                puts "src: $src" 
                puts "dst: $dst"
                puts "p: $p"
                puts "n: $n"
                puts "peer_descr: $peer_descr"
                puts "actions: $actions"
                puts "policy_items: $policy_items"
                puts "suppress_for: $suppress_for"
                puts "dropped: $dropped"
                puts "remote_location.country_code: $country_code"
                puts "remote_location.region: $region"
                puts "remote_location.city: $city"
                puts "remote_location.latitude: $latitude"
                puts "remote_location.longitude: $longitude"
                puts "metric_index.host: $mi_host"
                puts "metric_index.str: $mi_str"
                puts "metric_index.network: $mi_network"
            }

            set detail "Message: $msg Sub: $sub Src: $src Dst: $dst P: $p N: $n Peer Descr: $peer_descr Actions: $actions Policy Items: $policy_items Suppress For: $suppress_for Dropped: $dropped Country Code: $country_code Region: $region City: $city Lat.: $latitude Long.: $longitude MI Host: $mi_host MI Str: $mi_str MI Network: $mi_network"
            
            set GO 1

        }

    }
 
    if { $GO == 1 } {

        set message "Bro $note"
        set tmp_id [string range [md5::md5 -hex $note] 0 14]
        set sig_id [string range [scan $tmp_id %x] 0 7] 
        set rev "1"
        set priority $EVENT_PRIORITY
        set class $EVENT_CLASS

        # Build the event to send
        set event [list GenericEvent 0 $priority $class $HOSTNAME $nDate $AGENT_ID $NEXT_EVENT_ID \
                   $NEXT_EVENT_ID [string2hex $message] $src_ip $dst_ip 6 $src_port $dst_port \
                   $GEN_ID 4$sig_id $rev [string2hex $detail]]
    
        # Send the event to sguild
        if { $DEBUG } { puts "Sending: $event" }
            while { [catch {puts $sguildSocketID $event} tmpError] } {
    
            # Send to sguild failed
            if { $DEBUG } { puts "Send Failed: $tmpError" }
    
            # Close open socket
            catch {close $sguildSocketID}
            
            # Reconnect loop
            while { ![ConnectToSguild] } { after 15000 }

        }
    
        # Sguild response should be "ConfirmEvent eventID"
        if { [catch {gets $sguildSocketID response} readError] } {
    
            # Couldn't read from sguild
            if { $DEBUG } { puts "Read Failed: $readError" }

            # Close open socket
            catch {close $sguildSocketID}

            # Reconnect loop
            while { ![ConnectToSguilServer] } { after 15000 }
            return 0
    
        }

        if {$DEBUG} { puts "Received: $response" }
    
        if { [llength $response] != 2 || [lindex $response 0] != "ConfirmEvent" || [lindex $response 1] != $NEXT_EVENT_ID } {
    
            # Send to sguild failed
            if { $DEBUG } { puts "Recv Failed" }

            # Close open socket
            catch {close $sguildSocketID}

            # Reconnect loop
            while { ![ConnectToSguilServer] } { after 15000 }
            return 0                
    
        }
    
        # Success! Increment the next event id
        incr NEXT_EVENT_ID
    
    }

}

# Initialize connection to sguild
proc ConnectToSguilServer {} {

    global sguildSocketID HOSTNAME CONNECTED
    global SERVER_HOST SERVER_PORT DEBUG VERSION
    global AGENT_ID NEXT_EVENT_ID
    global AGENT_TYPE NET_GROUP

    # Connect
    if {[catch {set sguildSocketID [socket $SERVER_HOST $SERVER_PORT]}] > 0} {

        # Connection failed #

        set CONNECTED 0
        if {$DEBUG} {puts "Unable to connect to $SERVER_HOST on port $SERVER_PORT."}

    } else {

        # Connection Successful #
        fconfigure $sguildSocketID -buffering line

        # Version checks
        set tmpVERSION "$VERSION OPENSSL ENABLED"

        if [catch {gets $sguildSocketID} serverVersion] {
            puts "ERROR: $serverVersion"
            catch {close $sguildSocketID}
            exit 1
         }

        if { $serverVersion == "Connection Refused." } {

            puts $serverVersion
            catch {close $sguildSocketID}
            exit 1

        } elseif { $serverVersion != $tmpVERSION } {

            catch {close $sguildSocketID}
            puts "Mismatched versions.\nSERVER: ($serverVersion)\nAGENT: ($tmpVERSION)"
            return 0

        }

        if [catch {puts $sguildSocketID [list VersionInfo $tmpVERSION]} tmpError] {
            catch {close $sguildSocketID}
            puts "Unable to send version string: $tmpError"
            return 0
        }

        catch { flush $sguildSocketID }
        tls::import $sguildSocketID

        set CONNECTED 1
        if {$DEBUG} {puts "Connected to $SERVER_HOST"}

    }

    # Register the agent with sguild.
    set msg [list RegisterAgent $AGENT_TYPE $HOSTNAME $NET_GROUP]
    if { $DEBUG } { puts "Sending: $msg" }
    if { [catch { puts $sguildSocketID $msg } tmpError] } { 
 
        # Send failed
        puts "Error: $tmpError"
        catch {close $sguildSocketID} 
        return 0
    
    }

    # Read reply from sguild.
    if { [eof $sguildSocketID] || [catch {gets $sguildSocketID data}] } {
 
        # Read failed.
        catch {close $sockID} 
        return 0

    }
    if { $DEBUG } { puts "Received: $data" }

    # Process agent info returned from sguild
    # Should return:  AgentInfo sensorName agentType netName sensorID maxCid
    if { [lindex $data 0] != "AgentInfo" } {

        # This isn't what we were expecting
        catch {close $sguildSocketID}
        return 0

    }

    # AgentInfo    { AgentInfo [lindex $data 1] [lindex $data 2] [lindex $data 3] [lindex $data 4] [lindex $data 5]}
    set AGENT_ID [lindex $data 4]
    set NEXT_EVENT_ID [expr [lindex $data 5] + 1]

    return 1
    
}

proc Daemonize {} {

    global PID_FILE DEBUG

    # We need extended tcl to run in the background
    # Load extended tcl
    if [catch {package require Tclx} tclxVersion] {

        puts "ERROR: The tclx extension does NOT appear to be installed on this sysem."
        puts "Extended tcl (tclx) contains the 'fork' function needed to daemonize this"
        puts "process.  Install tclx or background the process manually.  Extended tcl"
        puts "(tclx) is available as a port/package for most linux and BSD systems."
        exit 1

    }

    set DEBUG 0
    set childPID [fork]
    # Parent exits.
    if { $childPID == 0 } { exit }
    id process group set
    if {[fork]} {exit 0}
    set PID [id process]
    if { ![info exists PID_FILE] } { set PID_FILE "/var/run/sensor_agent.pid" }
    set PID_DIR [file dirname $PID_FILE]

    if { ![file exists $PID_DIR] || ![file isdirectory $PID_DIR] || ![file writable $PID_DIR] } {

        puts "ERROR: Directory $PID_DIR does not exists or is not writable."
        puts "Process ID will not be written to file."

    } else {

        set pidFileID [open $PID_FILE w]
        puts $pidFileID $PID
        close $pidFileID

    }

}
#
# CheckLineFormat - Parses CONF_FILE lines to make sure they are formatted
#                   correctly (set varName value). Returns 1 if good.
#
proc CheckLineFormat { line } {

    set RETURN 1
    # Right now we just check the length and for "set".
    if { [llength $line] != 3 || [lindex $line 0] != "set" } { set RETURN 0 }
    return $RETURN

}

#
# A simple proc to return the current time in 'YYYY-MM-DD HH:MM:SS' format
#
proc GetCurrentTimeStamp {} {

    set timestamp [clock format [clock seconds] -gmt true -f "%Y-%m-%d %T"]
    return $timestamp

}

#
# Converts strings to hex
#
proc string2hex { s } {

    set i 0
    set r {}
    while { $i < [string length $s] } {

        scan [string index $s $i] "%c" tmp
        append r [format "%02X" $tmp]
        incr i

    }

    return $r

}


################### MAIN ###########################

# Standard options are below. If you need to add more switches,
# put them here. 
# 
# GetOpts
set state flag
foreach arg $argv {

    switch -- $state {

        flag {

            switch -glob -- $arg {

                -- { set state flag }
                -D { set DAEMON_CONF_OVERRIDE 1 }
                -c { set state conf }
                -O { set state sslpath }
                -f { set state filename }
                default { DisplayUsage $argv0 }

            }

        }

        conf     { set CONF_FILE $arg; set state flag }
        sslpath  { set TLS_PATH $arg; set state flag }
        filename { set FILENAME $arg; set state flag }
        default { DisplayUsage $argv0 }

    }

}

# Parse the config file here. Make sure you define the default config file location
if { ![info exists CONF_FILE] } {

    # No conf file specified check the defaults
    if { [file exists /etc/bro_agent.conf] } {

        set CONF_FILE /etc/bro_agent.conf

    } elseif { [file exists ./bro_agent.conf] } {

        set CONF_FILE ./bro_agent.conf

    } else {

        puts "Couldn't determine where the bro_agent.tcl config file is"
        puts "Looked for /etc/bro_agent.conf and ./bro_agent.conf."
        DisplayUsage $argv0

    }

}

set i 0
if { [info exists CONF_FILE] } {

    # Parse the config file. Currently the only option is to
    # create a variable using 'set varName value'
    set confFileID [open $CONF_FILE r]
    while { [gets $confFileID line] >= 0 } {

        incr i
        if { ![regexp ^# $line] && ![regexp ^$ $line] } {

            if { [CheckLineFormat $line] } {

                if { [catch {eval $line} evalError] } {

                    puts "Error at line $i in $CONF_FILE: $line"
                    exit 1

                }

            } else {

                puts "Error at line $i in $CONF_FILE: $line"
                exit 1

            }

        }

    }

    close $confFileID

    if { ![info exists EVENT_PRIORITY] } { set $EVENT_PRIORITY 1 }
    if { ![info exists EVENT_CLASS] } { set $EVENT_CLASS misc-activity }

} else {

    DisplayUsage $argv0

}

# Command line overrides the conf file.
if {[info exists DAEMON_CONF_OVERRIDE] && $DAEMON_CONF_OVERRIDE} { set DAEMON 1}
if {[info exists DAEMON] && $DAEMON} {Daemonize}

# OpenSSL is required
# Need path?
if { [info exists TLS_PATH] } {

    if [catch {load $TLS_PATH} tlsError] {

        puts "ERROR: Unable to load tls libs ($TLS_PATH): $tlsError"
        DisplayUsage $argv0

    }

}

if { [catch {package require tls} tmpError] }  {

    puts "ERROR: Unable to load tls package: $tmpError"
    DisplayUsage $argv0

}

### Load MD5 support
if [catch {package require md5} md5Version] {
    puts "Error: Package md5 not found"
    exit
}

# Connect to sguild
while { ![ConnectToSguilServer] } {

    # Wait 15 secs before reconnecting
    after 15000
}

# Intialize the Agent
InitAgent

# This causes tcl to go to it's event loop
vwait FOREVER
