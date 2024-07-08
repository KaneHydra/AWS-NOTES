# -*- coding=utf-8 -*-
# pip install boto3
import os
import csv
import json
import boto3
# import logging
# from datetime import datetime
from aws_config import get_aws_keys
from typing import Union,List,Dict
from rich import print
from botocore.exceptions import ClientError

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
        password:Union[str,None]=None,
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
        print('success!')
        print(res)
    except iam.exceptions.EntityAlreadyExistsException:
        print('username already exist!')
    if password:
        try:
            res = iam.create_login_profile(
                UserName=username,
                Password=password,
                PasswordResetRequired=False
            )
            print('create password success!')
            print(res)
        except iam.exceptions.EntityAlreadyExistsException:
            print('password already exist!')
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
                res = iam.add_user_to_group(
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
            with open(KEY_STORAGE_PATH+username+'_accessKeys.csv',
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
        users:Union[str,List[str],None]=None,
    ):
    print('create group')
    # Create an IAM group
    try:
        res = iam.create_group(GroupName=groupname)
        print(res)
    except iam.exceptions.EntityAlreadyExistsException:
        print(f'group {groupname} exists!')
    if policies:
        # 檢查是否有Policy?
        if isinstance(policies,str):
            policies = [policies]
        print(f'\nattach group policies:')
        for policy in policies:
            print(policy)
            try:
                res = iam.attach_group_policy(GroupName=groupname,PolicyArn=policy)
                print(res)
            except iam.exceptions.EntityAlreadyExistsException:
                print('policy already exist!')
    if users:
        # 檢查是否在群組中?
        print('\nadd group:')
        if isinstance(users,str):
            users = [users]
        # Add the username to the group
        for user in users:
            print(f'{user=}')
            try:
                res = iam.add_user_to_group(
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
    password='Asd21609+',
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
    ACCESS_KEY,SECRET_KEY = get_aws_keys(key='ai0125AdminUser')

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
    password='Asd21609+',
    policies='arn:aws:iam::aws:policy/AdministratorAccess',
    tags={'Name':'ai0125SuperUser','UseCase':'RootAccess'},
    create_access_key=True
)

# 建立群組
create_group(
    iam,
    'ai0125class',
     policies='arn:aws:iam::aws:policy/AmazonS3FullAccess',
    users=['ai0125AdminUser']
)

create_group(
    iam,
    'ai0125classVPCuser',
    policies='arn:aws:iam::aws:policy/AmazonVPCFullAccess',
)

create_user(
    iam,
    'ai0125User',
    tags={'Name':'ai0125User','UseCase':'CommonUser'},
    groups='ai0125classVPCuser'
)
# 這個帳號沒有設定密碼, 無法登入



def create_bucket(bucket_name:str, region:Union[str,None]=None)->bool:
    """Create an S3 bucket in a specified region
    If a region is not specified, the bucket is created in the S3 default
    region (us-east-1).
    :param bucket_name: Bucket to create
    :param region: String region to create bucket in, e.g., 'us-west-2'
    :return: True if bucket created, else False
    """
    # Create bucket
    try:
        if region is None:
            s3_client = boto3.client('s3')
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client = boto3.client('s3', region_name=region)
            location = {'LocationConstraint': region}
            s3_client.create_bucket(Bucket=bucket_name,
                                    CreateBucketConfiguration=location)
    except ClientError as e:
        print(e)
        return False
    return True


def s3_upload_file(file_name:str, bucket:str, object_name:Union[str,None]=None)->bool:
    """Upload a file to an S3 bucket
    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)
    # Upload the file
    s3_client = boto3.client('s3')
    try:
        res = s3_client.upload_file(file_name, bucket, object_name)
        print(res)
    except ClientError as e:
        print(e)
        return False
    return True


def create_bucket_with_poicies(
        s3,
        bucket_name:str,
        bucket_file_path:str,
        region:Union[str,None]='us-east-1'
    )->bool:

    create_res = create_bucket(bucket_name,region)

    bucket_policy = {
        "Id": "Policy1613735718314",
        'Version': '2012-10-17',
        'Statement': [
            {
                "Sid": "Stmt1613735715412",
                "Action": ["s3:GetObject"],
                "Effect": "Allow",
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                "Principal": "*",
            }
        ]
    }
    # Convert the policy from JSON dict to string
    bucket_policy = json.dumps(bucket_policy)
    s3.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
    for root,dirs,files in os.walk(bucket_file_path):
        for file in files:
            file_path = os.path.join(root,file)
            print(f'upload file...\n'+file_path)
            upload_res = s3_upload_file(file_path,bucket_name,file)
            print(f'result: {upload_res}')
    return False


# Set the new policy
s3 = boto3.client('s3')

# 建立 S3 bucket
res = create_bucket_with_poicies(s3,'ai0125s3bucket','./ai0125/ai0125s3bucket01/')
res = create_bucket_with_poicies(s3,'ai0125s3bucket2','./ai0125/ai0125s3bucket02/')


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
