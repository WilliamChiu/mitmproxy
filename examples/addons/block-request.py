"""
Blocks request with given code

eg: mitmproxy -s ./examples/addons/block-request.py --set flow_expr="~u <regex> --set code=400"
"""

from mitmproxy import ctx
from mitmproxy import flowfilter
from mitmproxy import http


class BlockRequest:
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
            help='Code to close the connection with',
        )

    def configure(self, updated):
        if "flow_expr" in updated:
            if ctx.options.flow_expr is not None:
                self.flow_expr = flowfilter.parse(ctx.options.flow_expr)
        if "code" in updated:
            if ctx.options.code is not None:
                self.code = ctx.options.code

    def response(self, flow):
        if self.flow_expr(flow):
            flow.response = http.Response.make(
                self.code, headers=flow.response.headers
            )


addons = [BlockRequest()]
