import json


def main():
    data = {"idosag8": {"password": "5e08ee1ceaec363b290490ef7036fdefa9b748b18a5af429554a3a3e03bd99b6",
                        "permission": "administrator", "files": {}, "shared_files": {}, "messages": [], "state": "offline"}}
    with open("users.json", "w") as json_write:
        json_write.write(json.dumps(data, json_write))

if __name__ == "__main__":
    main()