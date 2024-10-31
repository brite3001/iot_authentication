from sanic import Sanic, response
from sanic.response import text
from sanic_ext import Extend
import os
import socket
import aiofiles
import json
import pandas
import glob


from autogluon.tabular import TabularDataset, TabularPredictor

app = Sanic("MyHelloWorldApp")

app.config.CORS_ORIGINS = "*"
Extend(app)

hostname = socket.gethostname()

app.static("/static/", "static")

classification = TabularPredictor.load("models/good_classification")
classification.persist()

anomaly_detection = TabularPredictor.load("models/good_anomaly_detection")
anomaly_detection.persist()

authentication_model = TabularPredictor.load("models/good_authentication")
authentication_model.persist()


def authentication(fingerprints: list, expected_device: str):
    auth_data = []
    auth_data.append(expected_device)

    for fingerprint in fingerprints:
        fingerprint.pop()  # last element is empty string
        fingerprint = pandas.DataFrame(
            [fingerprint],
            columns=[
                "Feature 0",
                "Feature 1",
                "Feature 2",
                "Feature 3",
                "Feature 4",
                "Feature 5",
                "Feature 6",
            ],
        )
        fingerprint = TabularDataset(fingerprint)
        pred_class = classification.predict(fingerprint)
        pred_anomaly = anomaly_detection.predict(fingerprint)

        if pred_class[0] == expected_device and pred_anomaly[0] == "good":
            auth_data.append("match")
        elif pred_class[0] != expected_device and pred_anomaly[0] == "good":
            auth_data.append("mismatch")
        else:
            auth_data.append("malicious")

    auth_data = pandas.DataFrame(
        [auth_data],
        columns=[
            "label",
            "attempt_0",
            "attempt_1",
            "attempt_2",
            "attempt_3",
            "attempt_4",
            "attempt_5",
            "attempt_6",
            "attempt_7",
        ],
    )
    auth_data = TabularDataset(auth_data)

    auth_pred = authentication_model.predict(auth_data)

    return (pred_class, auth_pred)


# @app.get("/")
# async def hello_world(request):
#     print("this did something")
#     return text("Hello, world.")


async def write_file(path, body):
    async with aiofiles.open(path, "w") as f:
        await f.write(body)


async def save_fingerprint(fingerprints: list):
    if not os.path.exists(hostname + "/fingerprints/"):
        os.makedirs(hostname + "/fingerprints/")

    # Directory and pattern for your filenames
    current_dir = os.getcwd()
    pattern = f"/{hostname}/fingerprints/*.txt"
    pattern = current_dir + pattern

    print(pattern)

    # Identify highest existing number in directory
    max_number = len(glob.glob(pattern))

    file_path = f"{hostname}/fingerprints/f_{max_number + 1}.txt"

    await write_file(
        file_path, "\n".join(map(lambda sublist: " ".join(sublist), fingerprints))
    )


async def save_auth_result(auth_result: dict):
    if not os.path.exists(hostname + "/auth/"):
        os.makedirs(hostname + "/auth/")

    # Directory and pattern for your filenames
    current_dir = os.getcwd()
    pattern = f"/{hostname}/auth/*.json"
    pattern = current_dir + pattern

    print(pattern)

    # Identify highest existing number in directory
    max_number = len(glob.glob(pattern))

    print(max_number)

    file_path = f"{hostname}/auth/a_{max_number + 1}.json"

    await write_file(file_path, json.dumps(auth_result))


@app.post("/authentication")
async def process_upload(request):
    # Create upload folder if doesn't exist
    if not os.path.exists(hostname):
        os.makedirs(hostname)

    upload_file = request.files

    upload_file = json.loads(upload_file["file"][0].body.decode())

    # print(upload_file)
    # print(type(upload_file))

    # first element is always the devices claimed id.
    expected_device, is_malicious = upload_file.pop(0)
    fingerprints = []

    for fingerprint in upload_file:
        fingerprints.append(fingerprint.split("\n"))

    pred_class, auth_pred = authentication(fingerprints, expected_device)

    pred_class = "".join(list(pred_class))
    auth_pred = "".join(list(auth_pred))

    auth_results = {
        "predicted_class": pred_class,
        "attempted_to_authenticate_as": expected_device,
        "authentication_prediction": auth_pred,
        "is_malicious": is_malicious,
    }

    await save_fingerprint(fingerprints)

    await save_auth_result(auth_results)

    return response.json({"test": True})
