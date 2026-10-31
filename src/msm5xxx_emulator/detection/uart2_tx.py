"""Source-bound synchronous UART2 TX sink; no RX grant."""
import hashlib
from .arm import thumb_bl_target, thumb_literal_value

_SPEC = [(7996,
  28,
  'b62ed7014399c930059e4ee7723d85dbbc0eb884b8d01cbb63af4711d2e1604d',
  (),
  ((0, 1, 50333632), (10, 2, 50333184), (18, 2, 50333184), (22, 1, 50333616))),
 (7596,
  22,
  '265a0d9cb9a0affc9b7e6058513cb5b420d23c92436e0d78eb625464420a36bf',
  (),
  ((0, 0, 50333616), (10, 1, 50333184))),
 (7628,
  136,
  '589423c8824314ed7d3fdb5ea0c4570fcb740c30ae04de66095cfa5518808e27',
  ((34, 7596),),
  ((4, 1, 50333504),
   (18, 0, 895),
   (28, 0, 893),
   (40, 1, 50333648),
   (54, 1, 50333664),
   (60, 1, 50333632),
   (72, 1, 50333600),
   (78, 1, 50333616),
   (110, 0, 50333616),
   (118, 0, 50333616),
   (124, 1, 50333184))),
 (7128,
  108,
  '7886b1dcc98a98573ef6ac247f7b3b23bc76f1afe89796e098648b926b244714',
  ((16, 7596),
   (20, 7628),
   (24, 7080),
   (48, 6906),
   (64, 9244),
   (70, 9052),
   (74, 6906),
   (80, 7996),
   (86, 7996),
   (92, 7996),
   (98, 7996),
   (104, 7996)),
  ((8, 1, 50333312),
   (12, 1, 50333280),
   (30, 1, 50333296),
   (36, 1, 50333280),
   (40, 0, 50333328),
   (58, 0, 18770360),
   (68, 0, 18770360)))]

def find_uart2_tx_ready_pc(image: bytes) -> int | None:
    if not isinstance(image, bytes):
        return None
    for at,size,digest,calls,literals in _SPEC:
        if (not 0 <= at <= len(image)-size
                or hashlib.sha256(image[at:at+size]).hexdigest() != digest
                or any(thumb_bl_target(image,at+off) != target for off,target in calls)
                or any(thumb_literal_value(image,at+off,reg) != value
                       for off,reg,value in literals)):
            return None
    return 0x1f3e
