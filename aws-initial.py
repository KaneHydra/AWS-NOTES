# -*- coding=utf-8 -*-
# pip install boto3
import csv
import boto3
# import logging
from datetime import datetime
from aws_config import get_aws_keys
from typing import Union,List,Dict
from rich import print

KEY_STORAGE_PATH = './key/hydralisk.hk/'

# logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)
# formatter = logging.Formatter(
# 	'[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d] %(message)s',
# 	datefmt='%Y%m%d %H:%M:%S')
#
# ch = logging.StreamHandler()
# ch.setLevel(logging.DEBUG)
# ch.setFormatter(formatter)
#
# log_filename = datetime.now().strftime("%Y-%m-%d_%H_%M_%S.log")
# fh = logging.FileHandler(f'./log/{log_filename}')
# fh.setLevel(logging.DEBUG)
# fh.setFormatter(formatter)
#
# logger.addHandler(ch)
# logger.addHandler(fh)

ACCESS_KEY,SECRET_KEY = get_aws_keys(key='hk.root')
print(f'{ACCESS_KEY=}\n{SECRET_KEY=}')


# 用 root account 建立 Session
session = boto3.Session(
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    region_name='us-east-1'  # Replace with your desired region
)


def create_user(
        iam,
        username:str,
        policies:Union[str,List[str],None]=None,
        groups:Union[str,List[str],None]=None,
        tags:Union[Dict[str,str],None]=None,
        create_access_key:bool=False
    )->Union[Dict[str,str],None]:
    print(f'\ncreate username:')
    # Create the IAM username
    try:
        # 檢查是否有username?
        res = iam.create_user(UserName=username)
        print('success!\n'+res)
    except iam.exceptions.EntityAlreadyExistsException:
        print('username already exist!')
    # Attach AdministratorAccess policies to the username
    if policies:
        # 檢查是否有Policy?
        if isinstance(policies,str):
            policies = [policies]
        print(f'\nattach username policies:')
        for policy in policies:
            print(policy)
            try:
                res = iam.attach_user_policy(UserName=username,PolicyArn=policy)
                print(res)
            except iam.exceptions.EntityAlreadyExistsException:
                print('policy already exist!')
    if tags:
        # 檢查是否有Tag?
        # Add tags to the username
        try:
            print(f'\ntag username:')
            res = iam.tag_user(
                UserName=username,
                Tags=[{'Key':k,'Value':v} for k,v in tags.items()]
            )
            print(res)
        except iam.exceptions.EntityAlreadyExistsException:
            print('tag already exist!')
    if groups:
        # 檢查是否在群組中?
        print('\nadd group:')
        if isinstance(groups,str):
            groups = [groups]
        # Add the username to the group
        for group in groups:
            print(f'{group=}')
            try:
                res = iam.client.add_user_to_group(
                    UserName=username,
                    GroupName=group
                )
                print(res)
            except iam.exceptions.EntityAlreadyExistsException:
                print('username already in group!')
    if create_access_key:
        print('\ncreate access key')
        # 先檢查 是否存在 access key, 且是否有檔案在本地
        try:
            res = iam.create_access_key(UserName=username)
        except iam.exceptions.LimitExceededException as e:
            print(e)
            return None
        # {
        #     'AccessKey': {
        #         'UserName': 'ai0125SuperUser',
        #         'AccessKeyId': '',
        #         'Status': 'Active',
        #         'SecretAccessKey': '',
        #         'CreateDate': datetime.datetime(2024, 6, 12, 3, 29, 39, tzinfo=tzutc())
        #     },
        #     'ResponseMetadata': {
        #         'RequestId': '560a725d-e14a-4276-85d0-dba65bf11ac6',
        #         'HTTPStatusCode': 200,
        #         'HTTPHeaders': {
        #             'date': 'Wed, 12 Jun 2024 03:29:38 GMT',
        #             'x-amzn-requestid': '560a725d-e14a-4276-85d0-dba65bf11ac6',
        #             'content-type': 'text/xml',
        #             'content-length': '557'
        #         },
        #         'RetryAttempts': 0
        #     }
        # }
        if res:
            print(res)
            access_key = res['AccessKey']
            with open(KEY_STORAGE_PATH+username+'_credentials.csv',
                      mode='w',encoding='utf-8-sig',newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Access key ID','Secret access key'])
                writer.writerow([access_key['AccessKeyId'],access_key['SecretAccessKey']])
            return access_key
    return None


def detach_user_policy(name:str,policy:str):
    # Detach AdministratorAccess policy to the user
    print(f"IAM.detach_user_policy(\n\tUserName='{name}',\n\tPolicyArn='{policy}')\n")
    try:
        iam.detach_user_policy(UserName=name,PolicyArn=policy)
        print('Detach user policy success!')
    except iam.exceptions.NoSuchEntityException as e:
        print(e)


def create_group(
        iam,
        groupname:str,
        policies:Union[str,List[str],None]=None,
        tags:Union[Dict[str,str],None]=None,
        users:Union[str,List[str],None]=None,
    ):
    print('create group')
    # Create an IAM group
    res = iam.create_group(GroupName=groupname)
    print(res)
    if policies:
        # 檢查是否有Policy?
        if isinstance(policies,str):
            policies = [policies]
        print(f'\nattach group policies:')
        for policy in policies:
            print(policy)
            try:
                res = iam.attach_group_policy(UserName=username,PolicyArn=policy)
                print(res)
            except iam.exceptions.EntityAlreadyExistsException:
                print('policy already exist!')
    if tags:
        # 檢查是否有Tag?
        # Add tags to the username
        try:
            print(f'\ntag group:')
            res = iam.tag_group(
                UserName=username,
                Tags=[{'Key':k,'Value':v} for k,v in tags.items()]
            )
            print(res)
        except iam.exceptions.EntityAlreadyExistsException:
            print('tag already exist!')
    if users:
        # 檢查是否在群組中?
        print('\nadd group:')
        if isinstance(users,str):
            users = [users]
        # Add the username to the group
        for user in users:
            print(f'{user=}')
            try:
                res = iam.client.add_user_to_group(
                    UserName=user,
                    GroupName=groupname
                )
                print(res)
            except iam.exceptions.EntityAlreadyExistsException:
                print('username already in group!')


# Initialize the IAM client
iam = session.client('iam')

# 密碼用 Asd21609+
# 先建立 Admin User Account
admin_user_access_key = create_user(
    iam,
    'ai0125AdminUser',
    policies='arn:aws:iam::aws:policy/IAMFullAccess',
    tags={'Name':'ai0125AdminUser','UseCase':'Administration'},
    create_access_key=True
)

print('='*40+'\nAccessKey with ai0125AdminUser\n'+'='*40)
if admin_user_access_key:
    ACCESS_KEY = admin_user_access_key['AccessKeyId']
    SECRET_KEY = admin_user_access_key['SecretAccessKey']
else:
    print('get aws keys')
    ACCESS_KEY,SECRET_KEY = get_aws_keys(key='ai0125adminUser')

print(f'{ACCESS_KEY=}\n{SECRET_KEY=}')

# 用 Super User Account 建立 Session
session = boto3.Session(
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    region_name='us-east-1'  # Replace with your desired region
)

# 密碼用 Asd21609+
super_user_access_key = create_user(
    iam,
    'ai0125SuperUser',
    policies='arn:aws:iam::aws:policy/AdministratorAccess',
    tags={'Name':'ai0125SuperUser','UseCase':'RootAccess'},
    create_access_key=True
)

# 建立群組
create_group(
    iam,
    'ai0125class',
     policies= 'arn:aws:iam::aws:policy/AmazonS3FullAccess',
    tags={'Name':'ai0125class'},
    users=['ai0125AdminUser']
)

create_group(
    iam,
    'ai0125classVPCuser',
    policies='arn:aws:iam::aws:policy/AmazonVPCFullAccess',
    tags={'Name':'ai0125classVPCuser'}
)

create_user(
    iam,
    'ai0125User',
    tags={'Name':'ai0125User','UseCase':'CommonUser'},
    groups='ai0125classVPCuser'
)
# 這個帳號沒有設定密碼, 無法登入

# 建立 S3 bucket
# 開啓版本管理
# 開啓公開訪問權限
# 設定 BucketPolicy
# 上傳檔案
# 記得設定 Tags


# 建立 VPC
# vpc and more
# 名字爲 ai0125vpc-more-vpc
# IPv4 CIDR 爲 10.0.0.0/16
# Customize subnets CIDR blocks
# Public subnet CIDR block in us-east-1a
# 10.0.1.0/24
# Public subnet CIDR block in us-east-1b
# 10.0.2.0/24
# Private subnet CIDR block in us-east-1a
# 10.0.3.0/24
# Private subnet CIDR block in us-east-1b
# 10.0.4.0/24
# Tags 記得設定 Name

# 建立 EC2 Instance

# 建立 Cluster
# 建立 ngnix task

def delete_user(user_name):
    try:
        iam.User(user_name).delete()
        print(f"User {user_name} deleted successfully.")
    except Exception as e:
        print(f"Error deleting user {user_name}: {str(e)}")

# response = iam.detach_user_policy(
#     UserName='first_user',
#     PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
# )

client = boto3.client('iam')

print('\nList Groups\n')
# List all groups
group_res = iam.list_groups()
for group in group_res['Groups']:
    group_details = iam.get_group(GroupName=group['GroupName'])
    print(group['GroupName'])
    for user in group_details['Users']:
        print(" -", user['UserName'])


print('\nList Users\n')
user_data = client.list_users()
print(f'user_data:\n{user_data}\n')
user_name_list = [_['UserName'] for _ in user_data['Users']]
print(f'{user_name_list=}')
user_paginator = client.get_paginator('list_users')
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
policies_response = client.list_policies(
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
access_keys_info = client.list_access_keys()
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
    # inline_user_policies = client.list_user_policies(UserName=username)
    # print(f'{inline_user_policies=}')
    attached_policies = client.list_attached_user_policies(UserName=username)
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
