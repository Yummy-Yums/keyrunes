#!/bin/bash
cd /home/feanor/workspace/keyrunes
cargo run > /tmp/keyrunes_server.log 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > /tmp/keyrunes_server.pid
echo "Server started with PID: $SERVER_PID"
