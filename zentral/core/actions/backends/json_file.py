from datetime import datetime
import json
import os
from .base import BaseAction


class Action(BaseAction):
    def trigger(self, event, action_config_d):
        action_config_d = action_config_d or {}
        local_dir = self.config_d['local_dir']
        sub_dir = action_config_d.get('sub_dir', None)
        if sub_dir:
            local_dir = os.path.join(local_dir, sub_dir)
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)
        file_path = os.path.join(local_dir, datetime.now().isoformat())
        with open(file_path, 'w') as f:
            json.dump({'subject': event.get_notification_subject(),
                       'body': event.get_notification_body()},
                      f, sort_keys=True, indent=4)
