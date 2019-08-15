import logging

import websocket_server

logging.basicConfig(level=logging.INFO)

wss = websocket_server.WebSocketServer('127.0.0.1', 5005)

@wss.route('/ws/echo')
def handle_ws_echo(handler):
    seq = 0
    while True:
        msg = handler.read_next_message()
        if not msg:
            break
        msg_type, msg_text = msg
        msg = 'echo %s: %s' % (seq, msg_text)
        seq += 1
        handler.send_message(msg)

wss.serve_forever()
