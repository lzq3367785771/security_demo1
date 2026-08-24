import json
import os


def get_alarm_list():
    """
    从安全日志库读取告警
    """

    file_path = os.path.join(
        "data",
        "logs.json"
    )


    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as f:

        alarms = json.load(f)


    return alarms