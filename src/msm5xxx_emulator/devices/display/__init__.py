"""Display controller assembled from protocol-specific handlers."""

from .controller import DisplayControllerMixin
from .framebuffer import FramebufferMixin
from .protocols.bgr444 import Bgr444ProtocolMixin
from .protocols.direct import DirectProtocolMixin
from .protocols.packed import PackedProtocolMixin
from .protocols.page import PageProtocolMixin
from .protocols.rgb565 import Rgb565ProtocolMixin


class DisplayMixin(
    FramebufferMixin, PageProtocolMixin, Rgb565ProtocolMixin,
    Bgr444ProtocolMixin, PackedProtocolMixin, DirectProtocolMixin,
    DisplayControllerMixin,
):
    """Complete display device behavior."""


__all__ = ("DisplayMixin",)
