# -*- coding=utf-8 -*-
import csv
import configparser

key_dict = {
    # 'aws.root':'./key/hydralisk.aws/rootkey.csv',
    'hk.root':'./key/hydralisk.hk/rootkey.csv',
    # 'ai0125AdminUser':'./key/hydralisk.aws/ai0125AdminUser_accessKeys.csv',
    # 'ai0125SuperUser':'./key/hydralisk.aws/ai0125SuperUser_accessKeys.csv',
    'ai0125AdminUser':'./key/hydralisk.hk/ai0125AdminUser_accessKeys.csv',
    'ai0125SuperUser':'./key/hydralisk.hk/ai0125SuperUser_accessKeys.csv',
}

def get_aws_keys(key='root'):
    # Read credentials from CSV
    with open(key_dict[key], mode='r', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            print(f'{row=}')
            access_key_id = row['Access key ID']
            secret_access_key = row['Secret access key']
            # session_token = row['aws_session_token']
            # Use these credentials for further operations
            print(f'{access_key_id=},{secret_access_key=}')
            return access_key_id,secret_access_key
    raise KeyError


def main():
    ACCESS_KEY,SECRET_KEY = get_aws_keys(key='aws.root')
    print(f'{ACCESS_KEY=}\n{SECRET_KEY=}')
    config = configparser.ConfigParser()
    print(f'{config.sections()=}')
    print(f"{config.read('~/.aws/credentials')=}")
    print(f'{config.sections()=}')
    print(f"{config.read('~/.aws/config')=}")
    print(f'{config.sections()=}')


if __name__ == "__main__":
    main()
