import logging
from django import forms
import requests
from .base import BaseAction, BaseActionForm

logger = logging.getLogger('zentral.core.actions.backends.trello')


class TrelloClient(object):
    """Trello API Client"""
    API_BASE_URL = "https://api.trello.com/1"

    def __init__(self, app_key, token):
        super(TrelloClient, self).__init__()
        self.common_args = {
            "key": app_key,
            "token": token
            }

    def get_board(self, board_name):
        url = "%s/members/me/boards" % self.API_BASE_URL
        args = self.common_args.copy()
        args["fields"] = "name"
        r = requests.get(url, data=args)
        if not r.ok:
            logger.error(r.text)
            r.raise_for_status()
        existing_boards = r.json()
        for existing_board in existing_boards:
            if existing_board["name"].lower() == board_name.lower():
                return existing_board["id"]
        raise ValueError("board not found")

    def get_list(self, board_id, list_name):
        url = "%s/boards/%s/lists" % (self.API_BASE_URL, board_id)
        args = self.common_args.copy()
        args["fields"] = "name"
        r = requests.get(url, data=args)
        if not r.ok:
            logger.error(r.text)
            r.raise_for_status()
        existing_lists = r.json()
        for existing_list in existing_lists:
            if existing_list["name"].lower() == list_name.lower():
                return existing_list["id"]
        raise ValueError("list not found")

    def get_or_create_label(self, board_id, color, text):
        url = "%s/boards/%s/labels" % (self.API_BASE_URL, board_id)
        r = requests.get(url, data=self.common_args)
        if not r.ok:
            logger.error(r.text)
            r.raise_for_status()
        exisiting_labels = r.json()
        for exisiting_label in exisiting_labels:
            if exisiting_label["name"] == text and exisiting_label["color"] == color:
                return exisiting_label["id"]
        # not found - create label
        args = self.common_args.copy()
        args["name"] = text
        args["color"] = color
        r = requests.post(url, data=args)
        if not r.ok:
            logger.error(r.text)
            r.raise_for_status()
        new_label = r.json()
        return new_label["id"]

    def create_card(self, board_name, list_name, name, desc, labels=None):
        # labels = [{"name": "bla", "color": "red"},{"color": "green"}
        board_id = self.get_board(board_name)
        list_id = self.get_list(board_id, list_name)
        if labels is None:
            labels = []
        id_labels = []
        for label in labels:
            if "name" not in label:
                label["name"] = ""
            id_labels.append(self.get_or_create_label(board_id, label["color"], label["name"]))
        args = self.common_args.copy()
        args.update({"name": name,
                     "due": None,
                     "idList": list_id,
                     "desc": desc,
                     "idLabels": id_labels,
                     "pos": "top"})
        url = "%s/cards" % self.API_BASE_URL
        r = requests.post(url, data=args)
        if not r.ok:
            logger.error(r.text)
            r.raise_for_status()


class ActionForm(BaseActionForm):
    board = forms.CharField()
    list = forms.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ("board", "list"):
            default_value = self.config_d.get("default_{}".format(field_name), None)
            if default_value:
                self.fields[field_name].initial = default_value


class Action(BaseAction):
    action_form_class = ActionForm

    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.client = TrelloClient(config_d["application_key"],
                                   config_d["token"])
        self.default_board = config_d.get("default_board", None)
        self.default_list = config_d.get("default_list", None)

    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        board_name = action_config_d.get("board", self.default_board)
        if not board_name:
            raise ValueError("No board name")
        list_name = action_config_d.get("list", self.default_list)
        if not list_name:
            raise ValueError("No list name")
        self.client.create_card(board_name, list_name,
                                event.get_notification_subject(probe),
                                event.get_notification_body(probe),
                                action_config_d.get('labels', []))
