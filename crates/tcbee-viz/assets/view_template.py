"""Data of a plot exported by tcbee-viz.

Loads the plotted series and their missing events (hook_seq gaps) in the
exported time range with the tcbee Python package. Plot them below with the
library of your choice.
"""

import tcbee

DB = {{DB}}
# Exported time range in ns since boot, half-open [START_NS, END_NS)
START_NS, END_NS = {{START_NS}}, {{END_NS}}
# The plot showed seconds since ORIGIN_NS
ORIGIN_NS = {{ORIGIN_NS}}
# The visible value range (low, high), or None
YLIM = {{YLIM}}
# (flow id, source, name, direction, label, colour)
SERIES = [
{{SERIES}}]

data = {}  # label -> tcbee.Samples with ts_ns, seq and values
gaps = {}  # label -> list of tcbee.Gap, or None if unknown
with tcbee.open(DB) as db:
    for flow_id, source, name, direction, label, _color in SERIES:
        series = db.flow(flow_id).series().one(source=source, name=name, direction=direction)
        data[label] = series.read(start_ns=START_NS, end_ns=END_NS)
        gaps[label] = series.gaps(start_ns=START_NS, end_ns=END_NS)

# Plot here, for example with matplotlib:
#
# import matplotlib.pyplot as plt
#
# fig, ax = plt.subplots()
# for *_, label, color in SERIES:
#     t = [(ts - ORIGIN_NS) / 1e9 for ts in data[label].ts_ns]
#     ax.plot(t, data[label].values, label=label, color=color)
#     for gap in gaps[label] or []:
#         ax.axvspan((gap.start_ns - ORIGIN_NS) / 1e9, (gap.end_ns - ORIGIN_NS) / 1e9, alpha=0.3)
# ax.set_xlabel("Time (s)")
# if YLIM:
#     ax.set_ylim(YLIM)
# ax.legend()
# plt.show()
