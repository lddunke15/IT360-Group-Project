import pandas as pd

df = pd.read_json("login_logs.json")

# Example feature
attempts_per_ip = df.groupby("ip").size()
print(attempts_per_ip)
