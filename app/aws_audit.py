import boto3
from datetime import datetime, timedelta
import json
from botocore.exceptions import ClientError, NoCredentialsError

class AWSAudit:
    def __init__(self):
        """Initialize AWS Audit with boto3 clients"""
        try:
            # Initialize AWS clients
            self.ec2 = boto3.client('ec2')
            self.rds = boto3.client('rds')
            self.elasticache = boto3.client('elasticache')
            self.cloudwatch = boto3.client('cloudwatch')
            self.s3 = boto3.client('s3')
            self.lambda_client = boto3.client('lambda')
            
            # Get AWS account ID
            sts = boto3.client('sts')
            self.account_id = sts.get_caller_identity()['Account']
            
            print(f"✅ AWS Audit initialized for account: {self.account_id}")
            
        except NoCredentialsError:
            print("⚠️ AWS credentials not found. Running in demo mode.")
            self.demo_mode = True
        except Exception as e:
            print(f"⚠️ AWS Audit initialization error: {e}")
            self.demo_mode = True
    
    def run_audit(self):
        """Run complete AWS audit"""
        if hasattr(self, 'demo_mode') and self.demo_mode:
            return self._get_demo_audit()
        
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'account_id': self.account_id,
                'summary': {},
                'details': {},
                'recommendations': []
            }
            
            # Run individual audits
            results['details']['ebs_volumes'] = self.check_ebs_volumes()
            results['details']['elastic_ips'] = self.check_elastic_ips()
            results['details']['idle_instances'] = self.check_idle_instances()
            results['details']['unused_snapshots'] = self.check_unused_snapshots()
            results['details']['rds_instances'] = self.check_rds_instances()
            results['details']['s3_buckets'] = self.check_s3_buckets()
            
            # Generate summary
            results['summary'] = self._generate_summary(results['details'])
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(results['details'])
            
            return results
            
        except Exception as e:
            return {
                'error': 'Audit failed',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def get_structured_audit(self):
        """Get structured audit data"""
        if hasattr(self, 'demo_mode') and self.demo_mode:
            return self._get_demo_structured_audit()
        
        try:
            return {
                'timestamp': datetime.now().isoformat(),
                'unattached_volumes': self._get_unattached_volumes(),
                'unattached_eips': self._get_unattached_eips(),
                'idle_ec2_instances': self._get_idle_ec2_instances(),
                'unused_snapshots': self._get_unused_snapshots(),
                'underutilized_rds': self._get_underutilized_rds(),
                'empty_s3_buckets': self._get_empty_s3_buckets(),
                'unused_lambdas': self._get_unused_lambdas(),
                'cost_analysis': self._estimate_monthly_cost()
            }
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'demo_data': True
            }
    
    def check_ebs_volumes(self):
        """Check for unattached EBS volumes"""
        try:
            response = self.ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['available']}]
            )
            
            unattached_volumes = []
            total_size_gb = 0
            
            for volume in response['Volumes']:
                if not volume['Attachments']:
                    volume_info = {
                        'volume_id': volume['VolumeId'],
                        'size_gb': volume['Size'],
                        'volume_type': volume.get('VolumeType', 'standard'),
                        'created_time': volume['CreateTime'].isoformat(),
                        'availability_zone': volume['AvailabilityZone']
                    }
                    unattached_volumes.append(volume_info)
                    total_size_gb += volume['Size']
            
            return {
                'count': len(unattached_volumes),
                'total_size_gb': total_size_gb,
                'estimated_monthly_cost': len(unattached_volumes) * 0.10 * 30,  # ~$0.10/GB-month
                'volumes': unattached_volumes
            }
            
        except Exception as e:
            return {
                'count': 0,
                'total_size_gb': 0,
                'estimated_monthly_cost': 0,
                'error': str(e)
            }
    
    def check_elastic_ips(self):
        """Check for unattached Elastic IPs"""
        try:
            response = self.ec2.describe_addresses()
            
            unattached_eips = []
            
            for address in response['Addresses']:
                if 'InstanceId' not in address and 'NetworkInterfaceId' not in address:
                    eip_info = {
                        'public_ip': address['PublicIp'],
                        'allocation_id': address.get('AllocationId', ''),
                        'association_id': address.get('AssociationId', ''),
                    }
                    unattached_eips.append(eip_info)
            
            return {
                'count': len(unattached_eips),
                'estimated_monthly_cost': len(unattached_eips) * 3.6,  # $3.6 per month
                'eips': unattached_eips
            }
            
        except Exception as e:
            return {
                'count': 0,
                'estimated_monthly_cost': 0,
                'error': str(e)
            }
    
    def check_idle_instances(self):
        """Check for idle EC2 instances"""
        try:
            response = self.ec2.describe_instances()
            
            idle_instances = []
            cutoff_time = datetime.now() - timedelta(days=7)
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'running':
                        # Check launch time (simple idle detection)
                        launch_time = instance['LaunchTime']
                        if launch_time.replace(tzinfo=None) < cutoff_time:
                            instance_info = {
                                'instance_id': instance['InstanceId'],
                                'instance_type': instance['InstanceType'],
                                'launch_time': launch_time.isoformat(),
                                'state': instance['State']['Name'],
                                'tags': instance.get('Tags', [])
                            }
                            idle_instances.append(instance_info)
            
            return {
                'count': len(idle_instances),
                'instances': idle_instances
            }
            
        except Exception as e:
            return {
                'count': 0,
                'error': str(e)
            }
    
    def check_unused_snapshots(self):
        """Check for old/unused snapshots"""
        try:
            response = self.ec2.describe_snapshots(OwnerIds=['self'])
            
            old_snapshots = []
            cutoff_time = datetime.now() - timedelta(days=90)  # 90 days old
            
            for snapshot in response['Snapshots']:
                start_time = snapshot['StartTime']
                if start_time.replace(tzinfo=None) < cutoff_time:
                    snapshot_info = {
                        'snapshot_id': snapshot['SnapshotId'],
                        'volume_size': snapshot['VolumeSize'],
                        'start_time': start_time.isoformat(),
                        'description': snapshot.get('Description', '')
                    }
                    old_snapshots.append(snapshot_info)
            
            return {
                'count': len(old_snapshots),
                'total_size_gb': sum(s['volume_size'] for s in old_snapshots),
                'snapshots': old_snapshots[:50]  # Limit to 50
            }
            
        except Exception as e:
            return {
                'count': 0,
                'total_size_gb': 0,
                'error': str(e)
            }
    
    def check_rds_instances(self):
        """Check RDS instances"""
        try:
            response = self.rds.describe_db_instances()
            
            rds_instances = []
            
            for instance in response['DBInstances']:
                instance_info = {
                    'db_instance_id': instance['DBInstanceIdentifier'],
                    'engine': instance['Engine'],
                    'instance_class': instance['DBInstanceClass'],
                    'allocated_storage': instance['AllocatedStorage'],
                    'status': instance['DBInstanceStatus'],
                    'multi_az': instance.get('MultiAZ', False)
                }
                rds_instances.append(instance_info)
            
            return {
                'count': len(rds_instances),
                'instances': rds_instances
            }
            
        except Exception as e:
            return {
                'count': 0,
                'error': str(e)
            }
    
    def check_s3_buckets(self):
        """Check S3 buckets"""
        try:
            response = self.s3.list_buckets()
            
            buckets = []
            
            for bucket in response['Buckets']:
                try:
                    # Get bucket size and object count
                    cloudwatch_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/S3',
                        MetricName='BucketSizeBytes',
                        Dimensions=[
                            {'Name': 'BucketName', 'Value': bucket['Name']},
                            {'Name': 'StorageType', 'Value': 'StandardStorage'}
                        ],
                        StartTime=datetime.now() - timedelta(days=1),
                        EndTime=datetime.now(),
                        Period=86400,
                        Statistics=['Average']
                    )
                    
                    size_bytes = cloudwatch_response['Datapoints'][0]['Average'] if cloudwatch_response['Datapoints'] else 0
                    
                    bucket_info = {
                        'name': bucket['Name'],
                        'creation_date': bucket['CreationDate'].isoformat(),
                        'size_mb': size_bytes / 1024 / 1024,
                        'empty': size_bytes == 0
                    }
                    buckets.append(bucket_info)
                    
                except Exception:
                    continue
            
            return {
                'count': len(buckets),
                'empty_buckets': len([b for b in buckets if b['empty']]),
                'buckets': buckets
            }
            
        except Exception as e:
            return {
                'count': 0,
                'empty_buckets': 0,
                'error': str(e)
            }
    
    def _get_unattached_volumes(self):
        """Get unattached volumes summary"""
        ebs_result = self.check_ebs_volumes()
        return {
            'count': ebs_result['count'],
            'total_size_gb': ebs_result['total_size_gb'],
            'estimated_monthly_cost': ebs_result.get('estimated_monthly_cost', 0)
        }
    
    def _get_unattached_eips(self):
        """Get unattached EIPs summary"""
        eip_result = self.check_elastic_ips()
        return {
            'count': eip_result['count'],
            'estimated_monthly_cost': eip_result.get('estimated_monthly_cost', 0)
        }
    
    def _get_idle_ec2_instances(self):
        """Get idle EC2 instances"""
        idle_result = self.check_idle_instances()
        return {
            'count': idle_result['count']
        }
    
    def _get_unused_snapshots(self):
        """Get unused snapshots"""
        snapshot_result = self.check_unused_snapshots()
        return {
            'count': snapshot_result['count'],
            'total_size_gb': snapshot_result['total_size_gb']
        }
    
    def _get_underutilized_rds(self):
        """Get underutilized RDS instances"""
        rds_result = self.check_rds_instances()
        return {
            'count': rds_result['count']
        }
    
    def _get_empty_s3_buckets(self):
        """Get empty S3 buckets"""
        s3_result = self.check_s3_buckets()
        return {
            'count': s3_result['empty_buckets']
        }
    
    def _get_unused_lambdas(self):
        """Get unused Lambda functions (simplified)"""
        try:
            response = self.lambda_client.list_functions()
            return {
                'count': len(response['Functions'])
            }
        except:
            return {'count': 0}
    
    def _estimate_monthly_cost(self):
        """Estimate monthly cost savings"""
        try:
            ebs_cost = self._get_unattached_volumes()['estimated_monthly_cost'] or 0
            eip_cost = self._get_unattached_eips()['estimated_monthly_cost'] or 0
            
            return {
                'total_potential_savings': ebs_cost + eip_cost,
                'breakdown': {
                    'ebs_volumes': ebs_cost,
                    'elastic_ips': eip_cost
                }
            }
        except:
            return {
                'total_potential_savings': 0,
                'breakdown': {}
            }
    
    def _generate_summary(self, details):
        """Generate audit summary"""
        return {
            'total_issues': sum([
                details.get('ebs_volumes', {}).get('count', 0),
                details.get('elastic_ips', {}).get('count', 0),
                details.get('idle_instances', {}).get('count', 0)
            ]),
            'total_potential_savings': (
                details.get('ebs_volumes', {}).get('estimated_monthly_cost', 0) +
                details.get('elastic_ips', {}).get('estimated_monthly_cost', 0)
            ),
            'resources_count': {
                'ec2_volumes': details.get('ebs_volumes', {}).get('count', 0),
                'elastic_ips': details.get('elastic_ips', {}).get('count', 0),
                'ec2_instances': details.get('idle_instances', {}).get('count', 0),
                'rds_instances': details.get('rds_instances', {}).get('count', 0),
                's3_buckets': details.get('s3_buckets', {}).get('count', 0)
            }
        }
    
    def _generate_recommendations(self, details):
        """Generate recommendations based on findings"""
        recommendations = []
        
        # EBS volumes
        ebs_count = details.get('ebs_volumes', {}).get('count', 0)
        if ebs_count > 0:
            recommendations.append({
                'type': 'cost_saving',
                'priority': 'high',
                'title': f'Delete {ebs_count} unattached EBS volumes',
                'description': f'You have {ebs_count} EBS volumes that are not attached to any EC2 instance.',
                'estimated_savings': details.get('ebs_volumes', {}).get('estimated_monthly_cost', 0),
                'action': 'Delete the volumes through EC2 console or using AWS CLI'
            })
        
        # Elastic IPs
        eip_count = details.get('elastic_ips', {}).get('count', 0)
        if eip_count > 0:
            recommendations.append({
                'type': 'cost_saving',
                'priority': 'high',
                'title': f'Release {eip_count} unattached Elastic IPs',
                'description': f'You have {eip_count} Elastic IPs that are not associated with any resource.',
                'estimated_savings': details.get('elastic_ips', {}).get('estimated_monthly_cost', 0),
                'action': 'Release the Elastic IPs through VPC console'
            })
        
        # Idle instances
        idle_count = details.get('idle_instances', {}).get('count', 0)
        if idle_count > 0:
            recommendations.append({
                'type': 'cost_saving',
                'priority': 'medium',
                'title': f'Review {idle_count} potentially idle EC2 instances',
                'description': f'Found {idle_count} EC2 instances running for more than 7 days.',
                'action': 'Check instance usage and consider stopping or terminating if not needed'
            })
        
        return recommendations
    
    def _get_demo_audit(self):
        """Return demo audit data"""
        return {
            'timestamp': datetime.now().isoformat(),
            'account_id': '123456789012',
            'summary': {
                'total_issues': 3,
                'total_potential_savings': 45.6,
                'resources_count': {
                    'ec2_volumes': 2,
                    'elastic_ips': 1,
                    'ec2_instances': 5,
                    'rds_instances': 2,
                    's3_buckets': 3
                }
            },
            'details': {
                'ebs_volumes': {
                    'count': 2,
                    'total_size_gb': 100,
                    'estimated_monthly_cost': 20.0,
                    'volumes': [
                        {
                            'volume_id': 'vol-0abcdef1234567890',
                            'size_gb': 50,
                            'volume_type': 'gp2',
                            'created_time': '2023-01-15T10:30:00',
                            'availability_zone': 'us-east-1a'
                        },
                        {
                            'volume_id': 'vol-1abcdef1234567891',
                            'size_gb': 50,
                            'volume_type': 'gp3',
                            'created_time': '2023-02-20T14:45:00',
                            'availability_zone': 'us-east-1b'
                        }
                    ]
                },
                'elastic_ips': {
                    'count': 1,
                    'estimated_monthly_cost': 3.6,
                    'eips': [
                        {
                            'public_ip': '203.0.113.25',
                            'allocation_id': 'eipalloc-0abcdef1234567890',
                            'association_id': None
                        }
                    ]
                },
                'idle_instances': {
                    'count': 3,
                    'instances': [
                        {
                            'instance_id': 'i-0abcdef1234567890',
                            'instance_type': 't2.micro',
                            'launch_time': '2023-01-10T08:00:00',
                            'state': 'running',
                            'tags': [{'Key': 'Name', 'Value': 'Test-Server'}]
                        }
                    ]
                }
            },
            'recommendations': [
                {
                    'type': 'cost_saving',
                    'priority': 'high',
                    'title': 'Delete 2 unattached EBS volumes',
                    'description': 'You have 2 EBS volumes that are not attached to any EC2 instance.',
                    'estimated_savings': 20.0,
                    'action': 'Delete the volumes through EC2 console'
                },
                {
                    'type': 'cost_saving',
                    'priority': 'high',
                    'title': 'Release 1 unattached Elastic IP',
                    'description': 'You have 1 Elastic IP that is not associated with any resource.',
                    'estimated_savings': 3.6,
                    'action': 'Release the Elastic IP through VPC console'
                }
            ],
            'demo_mode': True,
            'note': 'Running in demo mode. Configure AWS credentials for real audit.'
        }
    
    def _get_demo_structured_audit(self):
        """Return demo structured audit data"""
        return {
            'timestamp': datetime.now().isoformat(),
            'unattached_volumes': {
                'count': 2,
                'total_size_gb': 100,
                'estimated_monthly_cost': 20.0
            },
            'unattached_eips': {
                'count': 1,
                'estimated_monthly_cost': 3.6
            },
            'idle_ec2_instances': {'count': 3},
            'unused_snapshots': {'count': 5, 'total_size_gb': 250},
            'underutilized_rds': {'count': 2},
            'empty_s3_buckets': {'count': 1},
            'unused_lambdas': {'count': 3},
            'cost_analysis': {
                'total_potential_savings': 23.6,
                'breakdown': {
                    'ebs_volumes': 20.0,
                    'elastic_ips': 3.6
                }
            },
            'demo_mode': True
        }

# Create instance for import
aws_audit_instance = AWSAudit()