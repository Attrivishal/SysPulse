# check_aws_resources.py
import boto3
import json
from datetime import datetime

print("=" * 70)
print("🔍 CHECKING ACTUAL AWS RESOURCES")
print("=" * 70)

session = boto3.Session()
sts = session.client('sts')
identity = sts.get_caller_identity()
print(f"Account: {identity['Account']}")
print(f"Region: {session.region_name}")
print(f"User: {identity['Arn']}")

# Check EC2 instances
print("\n" + "=" * 70)
print("EC2 INSTANCES")
print("=" * 70)
ec2 = session.client('ec2')

try:
    # Get all instances
    response = ec2.describe_instances()
    
    all_instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_info = {
                'InstanceId': instance['InstanceId'],
                'InstanceType': instance['InstanceType'],
                'State': instance['State']['Name'],
                'LaunchTime': instance['LaunchTime'].isoformat(),
                'Tags': instance.get('Tags', [])
            }
            all_instances.append(instance_info)
    
    print(f"Total EC2 Instances: {len(all_instances)}")
    
    if len(all_instances) > 0:
        print("\nInstance Details:")
        for i, instance in enumerate(all_instances, 1):
            print(f"{i}. {instance['InstanceId']} ({instance['InstanceType']}) - {instance['State']}")
            if instance['Tags']:
                tag_names = [f"{t['Key']}={t['Value']}" for t in instance['Tags']]
                print(f"   Tags: {', '.join(tag_names)}")
            print(f"   Launched: {instance['LaunchTime']}")
    else:
        print("No EC2 instances found!")
        
except Exception as e:
    print(f"Error listing EC2 instances: {e}")

# Check EBS volumes
print("\n" + "=" * 70)
print("EBS VOLUMES (Unattached)")
print("=" * 70)

try:
    response = ec2.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )
    
    unattached_volumes = []
    for volume in response['Volumes']:
        if not volume['Attachments']:
            volume_info = {
                'VolumeId': volume['VolumeId'],
                'Size': volume['Size'],
                'VolumeType': volume.get('VolumeType', 'standard'),
                'CreatedTime': volume['CreateTime'].isoformat()
            }
            unattached_volumes.append(volume_info)
    
    print(f"Unattached EBS Volumes: {len(unattached_volumes)}")
    
    if len(unattached_volumes) > 0:
        for i, volume in enumerate(unattached_volumes, 1):
            print(f"{i}. {volume['VolumeId']} - {volume['Size']}GB ({volume['VolumeType']})")
            print(f"   Created: {volume['CreatedTime']}")
    else:
        print("No unattached EBS volumes found!")
        
except Exception as e:
    print(f"Error listing EBS volumes: {e}")

# Check Elastic IPs
print("\n" + "=" * 70)
print("ELASTIC IPs (Unattached)")
print("=" * 70)

try:
    response = ec2.describe_addresses()
    
    unattached_eips = []
    for address in response['Addresses']:
        if 'InstanceId' not in address and 'NetworkInterfaceId' not in address:
            eip_info = {
                'PublicIp': address['PublicIp'],
                'AllocationId': address.get('AllocationId', 'N/A')
            }
            unattached_eips.append(eip_info)
    
    print(f"Unattached Elastic IPs: {len(unattached_eips)}")
    
    if len(unattached_eips) > 0:
        for i, eip in enumerate(unattached_eips, 1):
            print(f"{i}. {eip['PublicIp']} (Allocation: {eip['AllocationId']})")
    else:
        print("No unattached Elastic IPs found!")
        
except Exception as e:
    print(f"Error listing Elastic IPs: {e}")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("If you see resources above but not in your Flask app UI,")
print("the AWS Audit module might not be scanning correctly.")
print("=" * 70)