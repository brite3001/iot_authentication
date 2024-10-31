import glob
import os
import pandas as pd
import json
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix

working_dir = os.getcwd()
dirs_to_analyse = ["pop-os"]
df = pd.DataFrame()

for experiment_dir in dirs_to_analyse:
    pattern = f"{working_dir}/{experiment_dir}/auth/*.json"
    print(pattern)
    file_list = glob.glob(pattern)
    for file in file_list:
        with open(file) as f:  # replace 'file.json' with your filename
            data = json.load(f)
            df = pd.concat([df, pd.DataFrame([data])], ignore_index=True)

# melted_df = pd.melt(df, ["predicted_class"])
print(df["authentication_prediction"])

actual_auth = ["bad" for _ in range(len(df))]

# compute confusion matrix
conf_matrix = confusion_matrix(actual_auth, df["authentication_prediction"])
print("Confusion Matrix:")
print(conf_matrix)

print(classification_report(actual_auth, df["authentication_prediction"]))


# sns.histplot(data=df["authentication_prediction"])
# plt.show()

sns.set_palette("pastel")

plt.figure(figsize=(10, 5))

# Subplot 1
plt.subplot(2, 2, 1)
sns.histplot(data=df, x="authentication_prediction", hue="authentication_prediction")
plt.title("First Figure")

# Subplot 2
plt.subplot(2, 2, 2)
sns.histplot(
    data=df, x="attempted_to_authenticate_as", hue="attempted_to_authenticate_as"
)
plt.title("Second Figure")

# Subplot 3
plt.subplot(2, 2, 3)
sns.histplot(data=df, x="predicted_class", hue="predicted_class")
plt.title("Second Figure")

# Subplot 4
plt.subplot(2, 2, 4)
sns.histplot(data=df, x="is_malicious", hue="is_malicious")
plt.title("Second Figure")

plt.tight_layout()
plt.show()
