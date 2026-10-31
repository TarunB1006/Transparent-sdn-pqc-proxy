"""Stock ryu.app.simple_switch_13 plus a timestamp log of switch readiness.

A switch counts as ready when Ryu has processed its FEATURES_REPLY and
installed the table-miss entry, i.e. the control channel (and any proxy or
TLS layer underneath it) is fully up. One line per event: "<dpid>,<unix time>".
"""

import os
import time

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls

_LOG = os.environ.get("PQC_READY_LOG", "/tmp/pqc_ready.log")


class ReadyProbe(simple_switch_13.SimpleSwitch13):
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super().switch_features_handler(ev)
        with open(_LOG, "a") as fh:
            fh.write(f"{ev.msg.datapath.id},{time.time():.6f}\n")
