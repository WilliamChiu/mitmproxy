"""
Accepts websocket connections + http requests, then closes both with given codes

eg: mitmproxy -s ./examples/addons/block-request-and-websocket.py --set flow_expr="~u <regex> --set code=4000 --set flow_expr2="~u <regex> --set code2=400"
"""

from mitmproxy import ctx
from mitmproxy import flowfilter
from mitmproxy import http


class CloseWebsocket:
    def __init__(self) -> None:
        self.flow_expr = None
        self.code = None

    def load(self, loader):
        loader.add_option(
            name="flow_expr",
            typespec=str,
            default="",
            help='Eg: "~u <regex>"',
        )
        loader.add_option(
            name="code",
            typespec=int | None,
            default=None,
            help='Code to close the ws connection with',
        )
        loader.add_option(
            name="flow_expr2",
            typespec=str,
            default="",
            help='Eg: "~u <regex>"',
        )
        loader.add_option(
            name="code2",
            typespec=int | None,
            default=None,
            help='Code to close the http connection with',
        )

    def configure(self, updated):
        if "flow_expr" in updated:
            if ctx.options.flow_expr is not None:
                self.flow_expr = flowfilter.parse(ctx.options.flow_expr)
        if "code" in updated:
            if ctx.options.code is not None:
                self.code = ctx.options.code
        if "flow_expr2" in updated:
            if ctx.options.flow_expr2 is not None:
                self.flow_expr2 = flowfilter.parse(ctx.options.flow_expr2)
        if "code2" in updated:
            if ctx.options.code2 is not None:
                self.code2 = ctx.options.code2

    def websocket_message(self, flow: http.HTTPFlow):
        if self.flow_expr(flow):
            last_message = flow.websocket.messages[-1]
            if not last_message.from_client:
                last_message.drop()
                ctx.master.commands.call(
                    "inject.websocket",           # Command to invoke
                    flow,                         # Flow that we want to close
                    False,     # Whether we want to close the conn to the client
                    "Closed by proxy".encode(),   # Reason message to close the conn
                    False,                        # Whether we want to inject a TEXT opcode -> sending a message
                    True,                         # Whether we want to inject a CLOSE opcode -> closing the conn
                    self.code,
                )
    
    def response(self, flow):
        if self.flow_expr2(flow):
            flow.response = http.Response.make(
                self.code2, headers=flow.response.headers
            )


addons = [CloseWebsocket()]
