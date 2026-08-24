import json
import os


def get_device_status():
    """
    从模拟设备数据库读取状态
    """

    file_path = os.path.join(
        "data",
        "devices.json"
    )

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as f:

        devices = json.load(f)

    return devices