import json
import os
from datetime import datetime



def save_audit(alarm, action_result, ai_result):

    """
    保存安全事件审计记录
    """


    file_path = os.path.join(
        "data",
        "audit.json"
    )


    # 读取已有记录

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as f:

        records = json.load(f)



    # 新增记录

    record = {

        "event_id":
        "SEC-" + str(len(records)+1).zfill(3),


        "time":
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),


        "event":
        alarm["event"],


        "source_ip":
        alarm["source_ip"],


        "device":
        alarm["device"],


        "ai_analysis":
        ai_result,


        "action":
        action_result["action"],


        "target":
        action_result["target"],


        "result":
        action_result["status"]

    }


    records.append(record)



    # 写回文件

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            records,
            f,
            ensure_ascii=False,
            indent=4
        )


    return record