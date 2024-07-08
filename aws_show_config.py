# -*- coding=utf-8 -*-
# pip install boto3
import csv
import boto3
# import logging
# from datetime import datetime
from aws_config import get_aws_keys
from typing import Union,List,Dict
from rich import print

KEY_STORAGE_PATH = './key/hydralisk.hk/'

ACCESS_KEY,SECRET_KEY = get_aws_keys(key='hk.root')
print(f'{ACCESS_KEY=}\n{SECRET_KEY=}')

# 用 root account 建立 Session
session = boto3.Session(
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    region_name='us-east-1'  # Replace with your desired region
)

# Initialize the IAM client
iam = session.client('iam')

print('\nList Groups\n')
# List all groups
group_res = iam.list_groups()
for group in group_res['Groups']:
    group_details = iam.get_group(GroupName=group['GroupName'])
    print(group['GroupName'])
    for user in group_details['Users']:
        print(" -", user['UserName'])

print('\nList Users\n')
user_data = iam.list_users()
print(f'user_data:\n{user_data}\n')
user_name_list = [_['UserName'] for _ in user_data['Users']]
print(f'{user_name_list=}')
user_paginator = iam.get_paginator('list_users')
# {
#     "Users": [
#         {
#             "Path": "/",
#             "UserName": "ai0125SuperUser",
#             "UserId": "AIDAXYKJUFZLDF3CWWE4I",
#             "Arn": "arn:aws:iam::533267230294:user/ai0125SuperUser",
#             "CreateDate": datetime.datetime(2024, 6, 12, 3, 11, 12, tzinfo=tzutc()),
#         },
#         {}
#     ],
#     "IsTruncated": False,
#     "ResponseMetadata": {
#         "RequestId": "377c35e8-9cfb-45cd-a9e4-7b70cdf94dc3",
#         "HTTPStatusCode": 200,
#         "HTTPHeaders": {
#             "date": "Wed, 12 Jun 2024 03:29:39 GMT",
#             "x-amzn-requestid": "377c35e8-9cfb-45cd-a9e4-7b70cdf94dc3",
#             "content-type": "text/xml",
#             "content-length": "567"
#         },
#         "RetryAttempts": 0
#     }
# }
for res in user_paginator.paginate():
    print(f'\nuser:\n{res}')


print('\nList User Policies\n')
policies_response = iam.list_policies(
    Scope='AWS', # 'All'|'AWS'|'Local',
    OnlyAttached=True, # True|False,
    # PathPrefix='string',
    PolicyUsageFilter='PermissionsPolicy', # 'PermissionsPolicy'|'PermissionsBoundary',
    # Marker='string',
    # MaxItems=123
)
print(f'{policies_response=}')

policies_list = [_ for _ in policies_response['Policies']]
print(f"{policies_list=}")

print('\nList Access Keys:\n')
access_keys_info = iam.list_access_keys()
print(f'access_keys_info:\n{access_keys_info}\n')
# List access keys through the pagination interface.
access_keys_paginator = iam.get_paginator('list_access_keys')

for username in user_name_list:
    print(f'\n{username=}')
    for acc_key in access_keys_paginator.paginate(UserName=username):
        print(f'{acc_key=}')
        # Delete access key
        # for info in acc_key['AccessKeyMetadata']:
        #     iam.delete_access_key(
        #         AccessKeyId=info['AccessKeyId'],
        #         UserName=username
        #     )
    print('User Policies')
    # inline_user_policies = iam.list_user_policies(UserName=username)
    # print(f'{inline_user_policies=}')
    attached_policies = iam.list_attached_user_policies(UserName=username)
    print(f'attached_policies=\n{attached_policies}\n')
    # Print policy details
    for policy in attached_policies['AttachedPolicies']:
        print(f"Policy Name: {policy['PolicyName']}")
        print(f"Policy ARN: {policy['PolicyArn']}")
        print(f"Policy Description: {policy.get('Description', 'N/A')}\n")
        # detach_user_policy(username,policy['PolicyArn'])
    # Delete User
    # Delete a user
    # iam.delete_user(
    #     UserName=username
    # )

# ACCESS_KEY,SECRET_KEY = get_aws_keys(key='hk.root')
# print(f'{ACCESS_KEY=}\n{SECRET_KEY=}')

# super_user_access_key = create_user(
#     iam,
#     'ai0125AdminUser',
#     policies='arn:aws:iam::aws:policy/AdministratorAccess',
#     tags={'Name':'ai0125AdminUser','UseCase':'Administration'},
#     create_access_key=True
# )
#

# list existing buckets

# Retrieve the list of existing buckets
s3 = boto3.client('s3')
response = s3.list_buckets()

# Output the bucket names
print('Existing buckets:')
for bucket in response['Buckets']:
    print(f'\t{bucket["Name"]}')
    policy_res = s3.get_bucket_policy(Bucket=bucket['Name'])
    print(policy_res['Policy'])
