import base64
from xtrip_auth import XStripKeyConstruct, XStripKey

construct = XStripKeyConstruct("#P@$$W0R9")

assert(construct.generateKey('sha256').verify("#P@$$W0R9"))
