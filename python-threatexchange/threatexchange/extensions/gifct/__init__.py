# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

from threatexchange.extensions.manifest import ThreatExchangeExtensionManifest
from threatexchange.extensions.gifct.gifct_threatexchange_api import (
    GIFCTThreatExchangeSignalExchangeAPI,
)


TX_MANIFEST = ThreatExchangeExtensionManifest(
    apis=(GIFCTThreatExchangeSignalExchangeAPI,)
)
