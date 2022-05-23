import os
import sys

# zentral path
for rel_path in ("../../ee",
                 "../../ee/server",
                 "../../"):
    sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), rel_path)))
