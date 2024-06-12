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

detach_user_policy('aoi0125SuperUser','arn:aws:iam::aws:policy/AdministratorAccess')
delete_user('aoi0125SuperUser')

# def actually_delete_user(name:str):
#
