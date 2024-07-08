# -*- coding=utf-8 -*-
import boto3
from rich import print

# Initialize the IAM client
IAM = boto3.client('iam')

# errors = [e for e in dir(IAM.exceptions) if e.endswith('Exception')]
# print(errors)

def detach_user_policy(name:str,policy:str):
    # Detach AdministratorAccess policy to the user
    print(f"IAM.detach_user_policy(\n\tUserName='{name}',\n\tPolicyArn='{policy}')\n")
    try:
        IAM.detach_user_policy(UserName=name,PolicyArn=policy)
        print('Detach user policy success!')
    except IAM.exceptions.NoSuchEntityException as e:
        print(e)

def delete_user(name:str):
    # Delete a user
    print(f"IAM.delete_user(\n\tUserName='{name}'\n")
    try:
        IAM.delete_user(UserName=name)
        print('Delete user success!')
    except IAM.exceptions.NoSuchEntityException as e:
        print(e)



def delete_user1(iam,user_name):
    try:
        iam.User(user_name).delete()
        print(f"User {user_name} deleted successfully.")
    except Exception as e:
        print(f"Error deleting user {user_name}: {str(e)}")

# response = iam.detach_user_policy(
#     UserName='first_user',
#     PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
# )

# client = boto3.client('iam')

detach_user_policy('aoi0125SuperUser','arn:aws:iam::aws:policy/AdministratorAccess')
delete_user('aoi0125SuperUser')

# def actually_delete_user(name:str):
#


# empty bucket and delete bucket
s3 = boto3.client('s3')
response = s3.list_buckets()
print('Existing buckets:')
for bucket in response['Buckets']:
    print(f'\t{bucket["Name"]}')
    print('bucket Access Control List:')
    acl_result = s3.get_bucket_acl(Bucket=bucket['Name'])
    print(acl_result)
    print('Bucket Policy:')
    policy_res = s3.get_bucket_policy(Bucket=bucket['Name'])
    print(policy_res['Policy'])
    s3.delete_bucket_policy(Bucket=bucket['Name'])

