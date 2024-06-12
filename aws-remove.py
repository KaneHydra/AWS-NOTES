# -*- coding=utf-8 -*-
import sys
import csv
import boto3

key_dict = {
    'aws.root':'./key/hydralisk.aws/rootkey.csv',
    'hk.root':'./key/hydralisk.hk/rootkey.csv',
    'ai0125AdminUser':'./key/hydralisk.aws/ai0125AdminUser_accessKeys.csv',
    'ai0125SuperUser':'./key/hydralisk.aws/ai0125SuperUser_accessKeys.csv',
    'aoi0125AdminUser':'./key/hydralisk.hk/aoi0125AdminUser_accessKeys.csv',
    'aoi0125SuperUser':'./key/hydralisk.hk/aoi0125SuperUser_accessKeys.csv',
}

def get_key(key='root'):
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

ACCESS_KEY,SECRET_KEY = get_key(key='aws.root')

print(f'{ACCESS_KEY=},{SECRET_KEY=}')

if not (ACCESS_KEY and SECRET_KEY):
    print('get key failed!')
    sys.exit()


def get_unused_volumes():
    ec2 = boto3.resource('ec2', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY)
    unused_volumes = []
    for volume in ec2.volumes.all():
        if volume.state == 'available':
            attachments = volume.attachments
            if not attachments:
                # replace any non-breaking space characters with regular spaces in the volume ID
                volume_id = volume.id.replace('\u00A0', ' ')
                unused_volumes.append(volume_id)
    return unused_volumes

def delete_volumes(volumes):
    ec2 = boto3.resource('ec2', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY)
    for volume in volumes:
        print(f"Deleting volume {volume}")
        ec2.Volume(volume).delete()

def main():
    client = boto3.client('iam')
    user_response = client.list_users()
    print(f'{user_response=}')
    group_response = client.list_groups()
    print(f'{group_response=}')

    paginator = client.get_paginator('list_users')
    for i,res in enumerate(paginator.paginate()):
        print(f'{i=}, user: {res}')

    paginator = client.get_paginator('list_groups')
    for i,res in enumerate(paginator.paginate()):
        print(f'{i=}, group: {res}')

    s3_resource = boto3.resource(
        's3',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
    )

    # Use the S3 resource to access your buckets
    for i,bucket in enumerate(s3_resource.buckets.all()):
        print(f'{i=}, {bucket.name=}')

    return
    regions = [region['RegionName'] for region in boto3.client('ec2', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY).describe_regions()['Regions']]
    for region in regions:
        print(f'{region=}')
        # print(f"Checking for unused volumes in region {region}")
        boto3.setup_default_session(region_name=region)
        unused_volumes = get_unused_volumes()
        if unused_volumes:
            delete_volumes(unused_volumes)
            continue
        print(f"No unused volumes found in region {region}")

if __name__ == "__main__":
    main()
