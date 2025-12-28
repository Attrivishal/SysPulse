import boto3
from datetime import datetime, timedelta, timezone
import json
import csv
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from dataclasses import dataclass, asdict
from enum import Enum
import sys


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ResourceType(Enum):
    EC2 = "EC2"
    S3 = "S3"
    RDS = "RDS"
    LAMBDA = "LAMBDA"
    IAM = "IAM"
    VPC = "VPC"
    CLOUDFRONT = "CLOUDFRONT"
    DYNAMODB = "DYNAMODB"
    ECS = "ECS"
    SNS = "SNS"
    SQS = "SQS"
    ELASTICACHE = "ELASTICACHE"
    API_GATEWAY = "API_GATEWAY"
    CLOUDWATCH = "CLOUDFORMATION"
    CLOUDFORMATION = "CLOUDFORMATION"
    ROUTE53 = "ROUTE53"
    EFS = "EFS"
    EBS = "EBS"
    SECURITY_GROUP = "SECURITY_GROUP"


@dataclass
class AuditFinding:
    resource_type: ResourceType
    resource_id: str
    finding: str
    severity: Severity
    description: str
    recommendation: str
    estimated_savings: float = 0.0
    region: str = "ap-south-1"
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


class AWSComprehensiveAuditor:
    """
    Comprehensive AWS Auditor covering all essential services
    Used by professionals daily for cost optimization, security, and compliance
    """
    
    def __init__(self, region: str = 'us-east-1', profile: str = None):
        """
        Initialize AWS auditor with all essential service clients
        
        Args:
            region: AWS region
            profile: AWS profile name
        """
        self.region = region
        self.profile = profile
        self.demo_mode = False
        self.findings: List[AuditFinding] = []
        self.summary = {}
        
        # Initialize all essential AWS service clients
        self._init_clients()
        
        print(f"🚀 AWS Comprehensive Auditor initialized for region: {region}")
        print("📊 Services available: EC2, S3, RDS, Lambda, IAM, VPC, CloudFront, DynamoDB, ECS, SNS, SQS, ElastiCache, API Gateway, CloudWatch, CloudFormation, Route53, EFS")
    
    def _init_clients(self):
        """Initialize all AWS service clients used by professionals"""
        try:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            
            # Compute Services (Daily Use)
            self.ec2 = session.client('ec2')
            self.lambda_client = session.client('lambda')
            self.ecs = session.client('ecs')
            self.batch = session.client('batch')
            self.lightsail = session.client('lightsail')
            
            # Storage Services (Daily Use)
            self.s3 = session.client('s3')
            self.efs = session.client('efs')
            self.fsx = session.client('fsx')
            self.storage_gateway = session.client('storagegateway')
            
            # Database Services (Daily Use)
            self.rds = session.client('rds')
            self.dynamodb = session.client('dynamodb')
            self.elasticache = session.client('elasticache')
            self.redshift = session.client('redshift')
            self.docdb = session.client('docdb')
            self.neptune = session.client('neptune')
            
            # Networking (Daily Use)
            self.vpc = session.client('ec2')  # VPC uses EC2 client
            self.cloudfront = session.client('cloudfront')
            self.route53 = session.client('route53')
            self.api_gateway = session.client('apigateway')
            self.directconnect = session.client('directconnect')
            self.vpn = session.client('ec2')  # VPN uses EC2 client
            
            # Security & Identity (Daily Use)
            self.iam = session.client('iam')
            self.kms = session.client('kms')
            self.secretsmanager = session.client('secretsmanager')
            self.certificatemanager = session.client('acm')
            self.waf = session.client('wafv2')
            self.guardduty = session.client('guardduty')
            
            # Developer Tools (Daily Use)
            self.cloudwatch = session.client('cloudwatch')
            self.cloudtrail = session.client('cloudtrail')
            self.cloudformation = session.client('cloudformation')
            self.codedeploy = session.client('codedeploy')
            self.codebuild = session.client('codebuild')
            self.codepipeline = session.client('codepipeline')
            self.xray = session.client('xray')
            
            # Messaging & Integration (Daily Use)
            self.sns = session.client('sns')
            self.sqs = session.client('sqs')
            self.eventbridge = session.client('events')
            self.stepfunctions = session.client('stepfunctions')
            self.appsync = session.client('appsync')
            
            # Analytics & ML (Common)
            self.athena = session.client('athena')
            self.quicksight = session.client('quicksight')
            self.sagemaker = session.client('sagemaker')
            self.kinesis = session.client('kinesis')
            self.glue = session.client('glue')
            
            # Management & Governance (Daily Use)
            self.config = session.client('config')
            self.ssm = session.client('ssm')
            self.organizations = session.client('organizations')
            self.costexplorer = session.client('ce')
            self.backup = session.client('backup')
            
            # Get account info
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            self.user_arn = identity['Arn']
            
            print(f"✅ Account: {self.account_id} | User: {self.user_arn}")
            
        except (NoCredentialsError, EndpointConnectionError) as e:
            print(f"⚠️ AWS credentials not found or connection error: {e}")
            print("💡 Running in DEMO mode with sample data")
            self.demo_mode = True
        except Exception as e:
            print(f"❌ Initialization error: {e}")
            self.demo_mode = True
    
    # ==================== NEW: BACKWARD COMPATIBILITY METHODS ====================
    
    def get_structured_audit(self):
        """Get structured audit data for web dashboard - FIXED VERSION"""
        try:
            # Run quick individual audits
            ec2_data = self.audit_ec2_resources()
            s3_data = self.audit_s3_buckets()
            iam_data = self.audit_iam_resources()
            
            # Calculate total resources audited - FIXED!
            total_resources = 0
            
            # Count EC2 resources
            if isinstance(ec2_data, dict):
                if 'instances' in ec2_data and 'total' in ec2_data['instances']:
                    total_resources += ec2_data['instances']['total']
                
                if 'volumes' in ec2_data and 'total' in ec2_data['volumes']:
                    total_resources += ec2_data['volumes']['total']
                
                if 'elastic_ips' in ec2_data and 'total' in ec2_data['elastic_ips']:
                    total_resources += ec2_data['elastic_ips']['total']
                
                if 'snapshots' in ec2_data and 'total' in ec2_data['snapshots']:
                    total_resources += ec2_data['snapshots']['total']
                
                if 'amis' in ec2_data and 'total' in ec2_data['amis']:
                    total_resources += ec2_data['amis']['total']
                
                if 'security_groups' in ec2_data and 'total' in ec2_data.get('security_groups', {}):
                    total_resources += ec2_data['security_groups']['total']
            
            # Count IAM resources
            if isinstance(iam_data, dict):
                if 'users' in iam_data and 'total' in iam_data['users']:
                    total_resources += iam_data['users']['total']
                
                if 'roles' in iam_data and 'total' in iam_data['roles']:
                    total_resources += iam_data['roles']['total']
                
                if 'policies' in iam_data and 'total' in iam_data['policies']:
                    total_resources += iam_data['policies']['total']
            
            # Count S3 resources
            if isinstance(s3_data, dict) and 'total' in s3_data:
                total_resources += s3_data['total']
            
            # Calculate total savings
            total_savings = 0
            for finding in self.findings:
                total_savings += finding.estimated_savings
            
            # Convert findings to strings
            findings_list = []
            for f in self.findings:
                findings_list.append({
                    'resource_type': str(f.resource_type).replace("ResourceType.", ""),
                    'resource_id': f.resource_id,
                    'finding': f.finding,
                    'severity': str(f.severity).replace("Severity.", ""),
                    'description': f.description,
                    'recommendation': f.recommendation,
                    'estimated_savings': f.estimated_savings,
                    'region': f.region
                })
            
            # Prepare detailed structure
            structured_result = {
                'cost_analysis': {
                    'total_potential_savings': total_savings,
                    'estimated_monthly_cost': 0
                },
                'summary': {
                    'total_resources_audited': total_resources,  # THIS WAS FIXED!
                    'total_findings': len(self.findings),
                    'estimated_monthly_savings': total_savings
                },
                'details': {
                    'ec2': {
                        'instances': {
                            'total': ec2_data.get('instances', {}).get('total', 0),
                            'running': ec2_data.get('instances', {}).get('running', 0),
                            'stopped': ec2_data.get('instances', {}).get('stopped', 0)
                        },
                        'volumes': {
                            'attached': ec2_data.get('volumes', {}).get('attached', 0),
                            'unattached': ec2_data.get('volumes', {}).get('unattached', 0)
                        },
                        'elastic_ips': {
                            'attached': ec2_data.get('elastic_ips', {}).get('attached', 0),
                            'unattached': ec2_data.get('elastic_ips', {}).get('unattached', 0)
                        },
                        'snapshots': {
                            'total': ec2_data.get('snapshots', {}).get('total', 0),
                            'old': ec2_data.get('snapshots', {}).get('old', 0)
                        },
                        'amis': {
                            'total': ec2_data.get('amis', {}).get('total', 0),
                            'unused': ec2_data.get('amis', {}).get('unused', 0)
                        },
                        'findings': []
                    },
                    'iam': {
                        'users': {
                            'total': iam_data.get('users', {}).get('total', 0),
                            'with_mfa': iam_data.get('users', {}).get('with_mfa', 0),
                            'without_mfa': iam_data.get('users', {}).get('without_mfa', 0)
                        },
                        'roles': {
                            'total': iam_data.get('roles', {}).get('total', 0)
                        },
                        'policies': {
                            'total': iam_data.get('policies', {}).get('total', 0)
                        },
                        'access_keys': {
                            'total': iam_data.get('access_keys', {}).get('total', 0),
                            'old': iam_data.get('access_keys', {}).get('old', 0)
                        },
                        'findings': []
                    },
                    's3': {
                        'total': s3_data.get('total', 0),
                        'empty_buckets': s3_data.get('empty_buckets', []),
                        'large_buckets': s3_data.get('large_buckets', []),
                        'public_buckets': s3_data.get('public_buckets', []),
                        'unencrypted_buckets': s3_data.get('unencrypted_buckets', []),
                        'unversioned_buckets': s3_data.get('unversioned_buckets', []),
                        'details': s3_data.get('details', [])
                    }
                },
                'findings': findings_list,
                'status': 'success',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'region': self.region
            }
            
            print(f"✅ Structured audit complete!")
            print(f"📊 Total Resources Audited: {total_resources}")
            print(f"🔍 Total Findings: {len(self.findings)}")
            print(f"💰 Estimated Savings: ${total_savings:.2f}/month")
            
            return structured_result
            
        except Exception as e:
            print(f"❌ Structured audit failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'error': str(e),
                'status': 'failed',
                'summary': {
                    'total_resources_audited': 0,
                    'total_findings': 0,
                    'estimated_monthly_savings': 0
                }
            }
    
    def check_ec2_instances(self):
        """Compatibility method - alias for audit_ec2_resources"""
        return self.audit_ec2_resources()
    
    def check_s3_buckets(self):
        """Compatibility method - alias for audit_s3_buckets"""
        return self.audit_s3_buckets()
    
    def check_iam_users(self):
        """Compatibility method - alias for audit_iam_resources"""
        return self.audit_iam_resources()
    
    # ==================== RUN COMPLETE AUDIT ====================
    
    def run_complete_audit(self) -> Dict[str, Any]:
        """
        Run complete AWS audit covering ALL essential services
        Returns comprehensive audit report
        """
        print("\n" + "="*60)
        print("🚀 STARTING COMPREHENSIVE AWS AUDIT")
        print("="*60)
        
        if self.demo_mode:
            return self._generate_demo_report()
        
        audit_report = {
            'metadata': {
                'account_id': self.account_id,
                'region': self.region,
                'audit_timestamp': datetime.now(timezone.utc).isoformat(),
                'auditor_version': '2.1'
            },
            'services': {},
            'findings': [],
            'summary': {},
            'recommendations': []
        }
        
        try:
            # 1. COMPUTE SERVICES AUDIT
            print("\n🔍 [1/8] AUDITING COMPUTE SERVICES...")
            audit_report['services']['ec2'] = self.audit_ec2_resources()
            audit_report['services']['lambda'] = self.audit_lambda_functions()
            audit_report['services']['ecs'] = self.audit_ecs_clusters()
            audit_report['services']['batch'] = self.audit_batch_jobs()
            
            # 2. STORAGE SERVICES AUDIT
            print("🔍 [2/8] AUDITING STORAGE SERVICES...")
            audit_report['services']['s3'] = self.audit_s3_buckets()
            audit_report['services']['ebs'] = self.audit_ebs_volumes()
            audit_report['services']['efs'] = self.audit_efs_filesystems()
            
            # 3. DATABASE SERVICES AUDIT
            print("🔍 [3/8] AUDITING DATABASE SERVICES...")
            audit_report['services']['rds'] = self.audit_rds_instances()
            audit_report['services']['dynamodb'] = self.audit_dynamodb_tables()
            audit_report['services']['elasticache'] = self.audit_elasticache_clusters()
            
            # 4. NETWORKING SERVICES AUDIT
            print("🔍 [4/8] AUDITING NETWORKING SERVICES...")
            audit_report['services']['vpc'] = self.audit_vpc_resources()
            audit_report['services']['cloudfront'] = self.audit_cloudfront_distributions()
            audit_report['services']['route53'] = self.audit_route53_zones()
            audit_report['services']['api_gateway'] = self.audit_api_gateway()
            
            # 5. SECURITY SERVICES AUDIT
            print("🔍 [5/8] AUDITING SECURITY SERVICES...")
            audit_report['services']['iam'] = self.audit_iam_resources()
            audit_report['services']['security_groups'] = self.audit_security_groups()
            audit_report['services']['kms'] = self.audit_kms_keys()
            
            # 6. DEVELOPER TOOLS AUDIT
            print("🔍 [6/8] AUDITING DEVELOPER TOOLS...")
            audit_report['services']['cloudwatch'] = self.audit_cloudwatch()
            audit_report['services']['cloudformation'] = self.audit_cloudformation_stacks()
            audit_report['services']['code_services'] = self.audit_code_services()
            
            # 7. MESSAGING SERVICES AUDIT
            print("🔍 [7/8] AUDITING MESSAGING SERVICES...")
            audit_report['services']['sns'] = self.audit_sns_topics()
            audit_report['services']['sqs'] = self.audit_sqs_queues()
            audit_report['services']['eventbridge'] = self.audit_eventbridge()
            
            # 8. ANALYTICS & MANAGEMENT
            print("🔍 [8/8] AUDITING ANALYTICS & MANAGEMENT...")
            audit_report['services']['cost_analysis'] = self.analyze_costs()
            audit_report['services']['compliance'] = self.check_compliance()
            
            # Generate summary
            audit_report['summary'] = self._generate_summary(audit_report['services'])
            
            # Generate findings
            audit_report['findings'] = [asdict(f) for f in self.findings]
            
            # Generate recommendations
            audit_report['recommendations'] = self._generate_recommendations()
            
            print("\n✅ AUDIT COMPLETED SUCCESSFULLY!")
            print(f"📊 Total Findings: {len(self.findings)}")
            print(f"💰 Estimated Monthly Savings: ${audit_report['summary'].get('estimated_monthly_savings', 0):.2f}")
            
            return audit_report
            
        except Exception as e:
            print(f"\n❌ Audit failed: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    # ==================== COMPUTE SERVICES ====================
    
    def audit_ec2_resources(self) -> Dict[str, Any]:
        """Comprehensive EC2 resource audit - FIXED COUNTING"""
        print("  → EC2 Instances, AMIs, Snapshots, EIPs...")
        
        try:
            result = {
                'instances': {'running': 0, 'stopped': 0, 'total': 0, 'list': []},
                'volumes': {'attached': 0, 'unattached': 0, 'total': 0},
                'snapshots': {'total': 0, 'old': 0},
                'amis': {'total': 0, 'unused': 0},
                'elastic_ips': {'attached': 0, 'unattached': 0, 'total': 0},
                'security_groups': {'total': 0, 'overly_permissive': []},
                'findings': []
            }
            
            # 1. EC2 Instances
            instances = self.ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    state = instance['State']['Name']
                    result['instances']['total'] += 1
                    
                    if state == 'running':
                        result['instances']['running'] += 1
                        
                        # Check for idle instances
                        launch_time = instance['LaunchTime']
                        days_running = (datetime.now(timezone.utc) - launch_time).days
                        if days_running > 7 and instance.get('StateReason', {}).get('Code') != 'Client.UserInitiatedShutdown':
                            self.findings.append(AuditFinding(
                                resource_type=ResourceType.EC2,
                                resource_id=instance['InstanceId'],
                                finding="Potentially idle EC2 instance",
                                severity=Severity.MEDIUM,
                                description=f"Instance {instance['InstanceId']} has been running for {days_running} days",
                                recommendation="Consider stopping or terminating if not needed",
                                estimated_savings=5.0 * 30,  # Approx $5/day
                                region=self.region
                            ))
                    
                    elif state == 'stopped':
                        result['instances']['stopped'] += 1
                        
                        # Check long-stopped instances
                        self.findings.append(AuditFinding(
                            resource_type=ResourceType.EC2,
                            resource_id=instance['InstanceId'],
                            finding="Stopped EC2 instance",
                            severity=Severity.LOW,
                            description=f"Instance {instance['InstanceId']} is stopped but still incurs EBS costs",
                            recommendation="Terminate if not needed",
                            estimated_savings=2.0 * 30,  # Approx EBS costs
                            region=self.region
                        ))
                    
                    # Add to instance list
                    result['instances']['list'].append({
                        'id': instance['InstanceId'],
                        'type': instance.get('InstanceType', 'unknown'),
                        'state': state,
                        'launch_time': launch_time.isoformat() if 'LaunchTime' in instance else ''
                    })
            
            # 2. EBS Volumes
            volumes = self.ec2.describe_volumes()
            result['volumes']['total'] = len(volumes['Volumes'])
            for volume in volumes['Volumes']:
                if volume['State'] == 'available':
                    result['volumes']['unattached'] += 1
                    
                    self.findings.append(AuditFinding(
                        resource_type=ResourceType.EBS,
                        resource_id=volume['VolumeId'],
                        finding="Unattached EBS volume",
                        severity=Severity.HIGH,
                        description=f"Volume {volume['VolumeId']} ({volume['Size']}GB) is not attached to any instance",
                        recommendation="Delete if not needed",
                        estimated_savings=volume['Size'] * 0.10 * 30,  # $0.10/GB-month
                        region=self.region
                    ))
                else:
                    result['volumes']['attached'] += 1
            
            # 3. Snapshots
            snapshots = self.ec2.describe_snapshots(OwnerIds=['self'])
            result['snapshots']['total'] = len(snapshots['Snapshots'])
            
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=365)
            for snapshot in snapshots['Snapshots']:
                if snapshot['StartTime'] < cutoff_date:
                    result['snapshots']['old'] += 1
            
            # 4. Elastic IPs
            addresses = self.ec2.describe_addresses()
            result['elastic_ips']['total'] = len(addresses['Addresses'])
            for address in addresses['Addresses']:
                if 'InstanceId' not in address and 'NetworkInterfaceId' not in address:
                    result['elastic_ips']['unattached'] += 1
                    
                    self.findings.append(AuditFinding(
                        resource_type=ResourceType.EC2,
                        resource_id=address.get('AllocationId', address['PublicIp']),
                        finding="Unattached Elastic IP",
                        severity=Severity.HIGH,
                        description=f"Elastic IP {address['PublicIp']} is not associated",
                        recommendation="Release to avoid charges",
                        estimated_savings=3.6,  # $3.6/month
                        region=self.region
                    ))
                else:
                    result['elastic_ips']['attached'] += 1
            
            # 5. Security Groups
            sgs = self.vpc.describe_security_groups()
            result['security_groups']['total'] = len(sgs['SecurityGroups'])
            
            # Check for overly permissive security groups
            for sg in sgs['SecurityGroups']:
                for permission in sg.get('IpPermissions', []):
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = permission.get('FromPort')
                            to_port = permission.get('ToPort')
                            
                            risky_ports = [22, 3389, 1433, 3306, 5432, 1521]
                            if from_port in risky_ports or to_port in risky_ports:
                                result['security_groups']['overly_permissive'].append({
                                    'sg_id': sg['GroupId'],
                                    'sg_name': sg['GroupName'],
                                    'port': from_port,
                                    'cidr': '0.0.0.0/0'
                                })
                                
                                self.findings.append(AuditFinding(
                                    resource_type=ResourceType.SECURITY_GROUP,
                                    resource_id=sg['GroupId'],
                                    finding="Overly permissive security group",
                                    severity=Severity.HIGH,
                                    description=f"Security group {sg['GroupName']} allows {from_port} from 0.0.0.0/0",
                                    recommendation="Restrict to specific IP ranges",
                                    region=self.region
                                ))
            
            # 6. AMIs
            amis = self.ec2.describe_images(Owners=['self'])
            result['amis']['total'] = len(amis['Images'])
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ EC2 audit error: {e}")
            return {'error': str(e)}
    
    def audit_lambda_functions(self) -> Dict[str, Any]:
        """Audit Lambda functions for cost optimization"""
        print("  → Lambda Functions...")
        
        try:
            functions = self.lambda_client.list_functions()
            result = {
                'total': len(functions['Functions']),
                'by_runtime': {},
                'unused_functions': [],
                'large_functions': []
            }
            
            # Get CloudWatch metrics for invocation count
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
            
            for func in functions['Functions']:
                runtime = func['Runtime']
                result['by_runtime'][runtime] = result['by_runtime'].get(runtime, 0) + 1
                
                # Check for large functions
                if func['CodeSize'] > 50 * 1024 * 1024:  # 50MB
                    result['large_functions'].append(func['FunctionName'])
                
                # Check last modified
                last_modified = func['LastModified']
                if isinstance(last_modified, str):
                    last_modified = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
                
                if last_modified < cutoff_date:
                    result['unused_functions'].append(func['FunctionName'])
                    
                    self.findings.append(AuditFinding(
                        resource_type=ResourceType.LAMBDA,
                        resource_id=func['FunctionName'],
                        finding="Unused Lambda function",
                        severity=Severity.MEDIUM,
                        description=f"Function {func['FunctionName']} not modified in 30+ days",
                        recommendation="Review and delete if not needed",
                        region=self.region
                    ))
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ Lambda audit error: {e}")
            return {'error': str(e)}
    
    def audit_ecs_clusters(self) -> Dict[str, Any]:
        """Audit ECS clusters"""
        print("  → ECS Clusters...")
        try:
            response = self.ecs.list_clusters()
            clusters = response.get('clusterArns', [])
            
            result = {
                'total': len(clusters),
                'clusters': [],
                'details': []
            }
            
            if clusters:
                describe_response = self.ecs.describe_clusters(clusters=clusters)
                for cluster in describe_response.get('clusters', []):
                    cluster_info = {
                        'name': cluster.get('clusterName', 'Unknown'),
                        'status': cluster.get('status', 'UNKNOWN'),
                        'running_tasks': cluster.get('runningTasksCount', 0),
                        'pending_tasks': cluster.get('pendingTasksCount', 0),
                        'active_services': cluster.get('activeServicesCount', 0)
                    }
                    result['clusters'].append(cluster_info['name'])
                    result['details'].append(cluster_info)
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ ECS audit error: {e}")
            return {'error': str(e)}
    
    def audit_batch_jobs(self) -> Dict[str, Any]:
        """Audit Batch jobs"""
        print("  → Batch Jobs...")
        try:
            response = self.batch.describe_job_queues()
            result = {
                'total_queues': len(response.get('jobQueues', [])),
                'queues': [],
                'details': []
            }
            
            for queue in response.get('jobQueues', []):
                queue_info = {
                    'name': queue.get('jobQueueName', 'Unknown'),
                    'state': queue.get('state', 'UNKNOWN'),
                    'status': queue.get('status', 'UNKNOWN'),
                    'priority': queue.get('priority', 0)
                }
                result['queues'].append(queue_info['name'])
                result['details'].append(queue_info)
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ Batch audit error: {e}")
            return {'error': str(e)}
    
    # ==================== STORAGE SERVICES ====================
    
    def audit_s3_buckets(self) -> Dict[str, Any]:
        """Comprehensive S3 bucket audit with security checks - FIXED"""
        print("  → S3 Buckets (Security, Cost, Compliance)...")
        
        try:
            buckets = self.s3.list_buckets()
            result = {
                'total': len(buckets['Buckets']),
                'public_buckets': [],
                'unencrypted_buckets': [],
                'unversioned_buckets': [],
                'empty_buckets': [],
                'large_buckets': [],
                'details': []
            }
            
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                bucket_info = {
                    'name': bucket_name,
                    'creation_date': bucket['CreationDate'].isoformat()
                }
                
                try:
                    # Check if bucket is empty
                    objects = self.s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                    if 'Contents' not in objects:
                        result['empty_buckets'].append(bucket_name)
                        
                        self.findings.append(AuditFinding(
                            resource_type=ResourceType.S3,
                            resource_id=bucket_name,
                            finding="Empty S3 bucket",
                            severity=Severity.LOW,
                            description=f"Bucket {bucket_name} contains no objects",
                            recommendation="Delete if not needed",
                            region=self.region
                        ))
                    
                    # Check public access
                    try:
                        policy = self.s3.get_bucket_policy_status(Bucket=bucket_name)
                        if policy['PolicyStatus']['IsPublic']:
                            result['public_buckets'].append(bucket_name)
                            
                            self.findings.append(AuditFinding(
                                resource_type=ResourceType.S3,
                                resource_id=bucket_name,
                                finding="Public S3 bucket",
                                severity=Severity.CRITICAL,
                                description=f"Bucket {bucket_name} is publicly accessible",
                                recommendation="Review and restrict bucket policy",
                                region=self.region
                            ))
                    except:
                        pass
                    
                    # Check encryption
                    try:
                        self.s3.get_bucket_encryption(Bucket=bucket_name)
                    except:
                        result['unencrypted_buckets'].append(bucket_name)
                        
                        self.findings.append(AuditFinding(
                            resource_type=ResourceType.S3,
                            resource_id=bucket_name,
                            finding="Unencrypted S3 bucket",
                            severity=Severity.HIGH,
                            description=f"Bucket {bucket_name} has no encryption enabled",
                            recommendation="Enable SSE-S3 or SSE-KMS encryption",
                            region=self.region
                        ))
                    
                    # Check versioning
                    versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        result['unversioned_buckets'].append(bucket_name)
                
                except Exception as e:
                    bucket_info['error'] = str(e)
                
                result['details'].append(bucket_info)
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ S3 audit error: {e}")
            return {'error': str(e)}
    
    def audit_ebs_volumes(self) -> Dict[str, Any]:
        """Detailed EBS volume audit"""
        print("  → EBS Volumes...")
        
        try:
            volumes = self.ec2.describe_volumes()
            result = {
                'total': len(volumes['Volumes']),
                'by_type': {},
                'unattached': [],
                'underutilized': [],
                'cost_estimate': 0
            }
            
            for volume in volumes['Volumes']:
                vol_type = volume['VolumeType']
                result['by_type'][vol_type] = result['by_type'].get(vol_type, 0) + 1
                
                # Unattached volumes
                if volume['State'] == 'available':
                    result['unattached'].append({
                        'id': volume['VolumeId'],
                        'size': volume['Size'],
                        'type': vol_type
                    })
                    
                    # Cost estimation: ~$0.10 per GB-month
                    monthly_cost = volume['Size'] * 0.10
                    result['cost_estimate'] += monthly_cost
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ EBS audit error: {e}")
            return {'error': str(e)}
    
    def audit_efs_filesystems(self) -> Dict[str, Any]:
        """Audit EFS filesystems"""
        print("  → EFS Filesystems...")
        try:
            response = self.efs.describe_file_systems()
            result = {
                'total': len(response.get('FileSystems', [])),
                'encrypted': 0,
                'details': []
            }
            
            for fs in response.get('FileSystems', []):
                fs_info = {
                    'id': fs.get('FileSystemId', 'Unknown'),
                    'size': fs.get('SizeInBytes', {}).get('Value', 0),
                    'encrypted': fs.get('Encrypted', False),
                    'throughput_mode': fs.get('ThroughputMode', 'bursting')
                }
                
                if fs_info['encrypted']:
                    result['encrypted'] += 1
                
                result['details'].append(fs_info)
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ EFS audit error: {e}")
            return {'error': str(e)}
    
    # ==================== DATABASE SERVICES ====================
    
    def audit_rds_instances(self) -> Dict[str, Any]:
        """RDS instance audit for cost and performance"""
        print("  → RDS Instances...")
        
        try:
            instances = self.rds.describe_db_instances()
            result = {
                'total': len(instances['DBInstances']),
                'by_engine': {},
                'by_class': {},
                'multi_az': 0,
                'public': 0,
                'stopped': 0,
                'details': []
            }
            
            for db in instances['DBInstances']:
                engine = db['Engine']
                instance_class = db['DBInstanceClass']
                
                result['by_engine'][engine] = result['by_engine'].get(engine, 0) + 1
                result['by_class'][instance_class] = result['by_class'].get(instance_class, 0) + 1
                
                if db.get('MultiAZ', False):
                    result['multi_az'] += 1
                
                if db.get('PubliclyAccessible', False):
                    result['public'] += 1
                    
                    self.findings.append(AuditFinding(
                        resource_type=ResourceType.RDS,
                        resource_id=db['DBInstanceIdentifier'],
                        finding="Publicly accessible RDS instance",
                        severity=Severity.HIGH,
                        description=f"RDS instance {db['DBInstanceIdentifier']} is publicly accessible",
                        recommendation="Move to private subnet or use VPN",
                        region=self.region
                    ))
                
                if db['DBInstanceStatus'] == 'stopped':
                    result['stopped'] += 1
                    
                    self.findings.append(AuditFinding(
                        resource_type=ResourceType.RDS,
                        resource_id=db['DBInstanceIdentifier'],
                        finding="Stopped RDS instance",
                        severity=Severity.MEDIUM,
                        description=f"RDS instance {db['DBInstanceIdentifier']} is stopped",
                        recommendation="Delete if not needed to avoid storage costs",
                        region=self.region
                    ))
                
                result['details'].append({
                    'identifier': db['DBInstanceIdentifier'],
                    'engine': engine,
                    'class': instance_class,
                    'status': db['DBInstanceStatus'],
                    'storage': db['AllocatedStorage'],
                    'endpoint': db.get('Endpoint', {}).get('Address')
                })
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ RDS audit error: {e}")
            return {'error': str(e)}
    
    def audit_dynamodb_tables(self) -> Dict[str, Any]:
        """DynamoDB table audit"""
        print("  → DynamoDB Tables...")
        
        try:
            tables = self.dynamodb.list_tables()
            result = {
                'total': tables.get('TableNames', []),
                'count': len(tables.get('TableNames', [])),
                'details': []
            }
            
            for table_name in tables.get('TableNames', [])[:20]:  # Limit to 20
                try:
                    table_info = self.dynamodb.describe_table(TableName=table_name)
                    table = table_info['Table']
                    
                    result['details'].append({
                        'name': table_name,
                        'status': table['TableStatus'],
                        'items': table.get('ItemCount', 0),
                        'size_bytes': table.get('TableSizeBytes', 0),
                        'billing_mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED'),
                        'encryption': 'Enabled' if table.get('SSEDescription') else 'Disabled'
                    })
                except:
                    continue
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ DynamoDB audit error: {e}")
            return {'error': str(e)}
    
    def audit_elasticache_clusters(self) -> Dict[str, Any]:
        """Audit ElastiCache clusters"""
        print("  → ElastiCache Clusters...")
        try:
            response = self.elasticache.describe_cache_clusters()
            result = {
                'total': len(response.get('CacheClusters', [])),
                'by_engine': {},
                'details': []
            }
            
            for cluster in response.get('CacheClusters', []):
                engine = cluster.get('Engine', 'redis')
                result['by_engine'][engine] = result['by_engine'].get(engine, 0) + 1
                
                cluster_info = {
                    'id': cluster.get('CacheClusterId', 'Unknown'),
                    'engine': engine,
                    'status': cluster.get('CacheClusterStatus', 'UNKNOWN'),
                    'node_type': cluster.get('CacheNodeType', 'Unknown'),
                    'nodes': cluster.get('NumCacheNodes', 0)
                }
                result['details'].append(cluster_info)
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ ElastiCache audit error: {e}")
            return {'error': str(e)}
    
    # ==================== NETWORKING SERVICES ====================
    
    def audit_vpc_resources(self) -> Dict[str, Any]:
        """VPC resource audit"""
        print("  → VPC, Subnets, Route Tables...")
        
        try:
            # Get VPCs
            vpcs = self.vpc.describe_vpcs()
            result = {
                'vpcs': len(vpcs['Vpcs']),
                'subnets': 0,
                'route_tables': 0,
                'nat_gateways': 0,
                'internet_gateways': 0,
                'vpc_endpoints': 0
            }
            
            # Count subnets
            subnets = self.vpc.describe_subnets()
            result['subnets'] = len(subnets['Subnets'])
            
            # Count route tables
            route_tables = self.vpc.describe_route_tables()
            result['route_tables'] = len(route_tables['RouteTables'])
            
            # Check for default VPC
            for vpc in vpcs['Vpcs']:
                if vpc.get('IsDefault', False):
                    self.findings.append(AuditFinding(
                        resource_type=ResourceType.VPC,
                        resource_id=vpc['VpcId'],
                        finding="Default VPC in use",
                        severity=Severity.INFO,
                        description="Using default VPC for resources",
                        recommendation="Consider creating custom VPCs for production",
                        region=self.region
                    ))
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ VPC audit error: {e}")
            return {'error': str(e)}
    
    def audit_security_groups(self) -> Dict[str, Any]:
        """Security group audit for overly permissive rules"""
        print("  → Security Groups...")
        
        try:
            sgs = self.vpc.describe_security_groups()
            result = {
                'total': len(sgs['SecurityGroups']),
                'overly_permissive': [],
                'unused': []
            }
            
            # Get all network interfaces to find unused SGs
            interfaces = self.vpc.describe_network_interfaces()
            used_sgs = set()
            for interface in interfaces['NetworkInterfaces']:
                for sg in interface.get('Groups', []):
                    used_sgs.add(sg['GroupId'])
            
            for sg in sgs['SecurityGroups']:
                sg_id = sg['GroupId']
                
                # Check if unused
                if sg_id not in used_sgs:
                    result['unused'].append(sg_id)
                
                # Check for overly permissive rules
                for permission in sg.get('IpPermissions', []):
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            # Check if it's SSH, RDP, or database ports
                            from_port = permission.get('FromPort')
                            to_port = permission.get('ToPort')
                            
                            risky_ports = [22, 3389, 1433, 3306, 5432, 1521]
                            if from_port in risky_ports or to_port in risky_ports:
                                result['overly_permissive'].append({
                                    'sg_id': sg_id,
                                    'sg_name': sg['GroupName'],
                                    'port': from_port,
                                    'cidr': '0.0.0.0/0'
                                })
                                
                                self.findings.append(AuditFinding(
                                    resource_type=ResourceType.SECURITY_GROUP,
                                    resource_id=sg_id,
                                    finding="Overly permissive security group",
                                    severity=Severity.HIGH,
                                    description=f"Security group {sg['GroupName']} allows {from_port} from 0.0.0.0/0",
                                    recommendation="Restrict to specific IP ranges",
                                    region=self.region
                                ))
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ Security Group audit error: {e}")
            return {'error': str(e)}
    
    def audit_cloudfront_distributions(self) -> Dict[str, Any]:
        """CloudFront distribution audit"""
        print("  → CloudFront Distributions...")
        
        try:
            distributions = self.cloudfront.list_distributions()
            result = {
                'total': distributions['DistributionList'].get('Quantity', 0),
                'enabled': 0,
                'disabled': 0,
                'details': []
            }
            
            if 'Items' in distributions['DistributionList']:
                for dist in distributions['DistributionList']['Items']:
                    result['enabled' if dist['Enabled'] else 'disabled'] += 1
                    
                    result['details'].append({
                        'id': dist['Id'],
                        'domain': dist['DomainName'],
                        'status': dist['Status'],
                        'enabled': dist['Enabled'],
                        'price_class': dist.get('PriceClass', 'All')
                    })
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ CloudFront audit error: {e}")
            return {'error': str(e)}
    
    def audit_route53_zones(self) -> Dict[str, Any]:
        """Route53 hosted zones audit"""
        print("  → Route53 Hosted Zones...")
        
        try:
            zones = self.route53.list_hosted_zones()
            result = {
                'total': zones['HostedZones'],
                'public': 0,
                'private': 0,
                'details': []
            }
            
            for zone in zones['HostedZones']:
                is_private = zone.get('Config', {}).get('PrivateZone', False)
                
                if is_private:
                    result['private'] += 1
                else:
                    result['public'] += 1
                
                result['details'].append({
                    'id': zone['Id'],
                    'name': zone['Name'],
                    'private': is_private,
                    'record_count': zone.get('ResourceRecordSetCount', 0)
                })
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ Route53 audit error: {e}")
            return {'error': str(e)}
    
    # ==================== SECURITY SERVICES ====================
    
    def audit_iam_resources(self) -> Dict[str, Any]:
        """Comprehensive IAM resource audit - FIXED"""
        print("  → IAM Users, Roles, Policies...")
        
        try:
            result = {
                'users': {'total': 0, 'with_mfa': 0, 'without_mfa': 0, 'list': []},
                'roles': {'total': 0},
                'policies': {'total': 0},
                'access_keys': {'total': 0, 'old': 0},
                'findings': []
            }
            
            # Users
            users = self.iam.list_users()
            result['users']['total'] = len(users['Users'])
            
            for user in users['Users']:
                user_name = user['UserName']
                result['users']['list'].append(user_name)
                
                # Check MFA
                mfa_devices = self.iam.list_mfa_devices(UserName=user_name)
                if len(mfa_devices['MFADevices']) > 0:
                    result['users']['with_mfa'] += 1
                else:
                    result['users']['without_mfa'] += 1
                    
                    self.findings.append(AuditFinding(
                        resource_type=ResourceType.IAM,
                        resource_id=user_name,
                        finding="IAM user without MFA",
                        severity=Severity.HIGH,
                        description=f"User {user_name} does not have MFA enabled",
                        recommendation="Enable MFA immediately",
                        region=self.region
                    ))
                
                # Check access keys
                access_keys = self.iam.list_access_keys(UserName=user_name)
                result['access_keys']['total'] += len(access_keys['AccessKeyMetadata'])
                
                for key in access_keys['AccessKeyMetadata']:
                    key_age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    if key_age > 90:
                        result['access_keys']['old'] += 1
                        
                        self.findings.append(AuditFinding(
                            resource_type=ResourceType.IAM,
                            resource_id=key['AccessKeyId'],
                            finding="Old IAM access key",
                            severity=Severity.MEDIUM,
                            description=f"Access key {key['AccessKeyId']} for user {user_name} is {key_age} days old",
                            recommendation="Rotate access key",
                            region=self.region
                        ))
            
            # Roles
            roles = self.iam.list_roles()
            result['roles']['total'] = len(roles['Roles'])
            
            # Policies
            policies = self.iam.list_policies(Scope='Local')
            result['policies']['total'] = len(policies['Policies'])
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ IAM audit error: {e}")
            return {'error': str(e)}
    
    def audit_kms_keys(self) -> Dict[str, Any]:
        """Audit KMS keys"""
        print("  → KMS Keys...")
        try:
            response = self.kms.list_keys()
            result = {
                'total': len(response.get('Keys', [])),
                'details': []
            }
            
            for key in response.get('Keys', []):
                key_info = {
                    'id': key.get('KeyId', 'Unknown'),
                    'arn': key.get('KeyArn', 'Unknown')
                }
                result['details'].append(key_info)
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ KMS audit error: {e}")
            return {'error': str(e)}
    
    # ==================== DEVELOPER TOOLS ====================
    
    def audit_cloudwatch(self) -> Dict[str, Any]:
        """CloudWatch audit"""
        print("  → CloudWatch Logs, Alarms, Metrics...")
        
        try:
            # Alarms
            alarms = self.cloudwatch.describe_alarms()
            
            result = {
                'alarms': len(alarms.get('MetricAlarms', [])),
                'log_groups': 0,
                'alarm_states': {
                    'OK': 0,
                    'ALARM': 0,
                    'INSUFFICIENT_DATA': 0
                }
            }
            
            # Count alarm states
            for alarm in alarms.get('MetricAlarms', []):
                state = alarm.get('StateValue', 'INSUFFICIENT_DATA')
                result['alarm_states'][state] = result['alarm_states'].get(state, 0) + 1
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ CloudWatch audit error: {e}")
            return {'error': str(e)}
    
    def audit_cloudformation_stacks(self) -> Dict[str, Any]:
        """CloudFormation stack audit"""
        print("  → CloudFormation Stacks...")
        
        try:
            stacks = self.cloudformation.list_stacks()
            result = {
                'total': len(stacks['StackSummaries']),
                'by_status': {},
                'details': []
            }
            
            for stack in stacks['StackSummaries']:
                status = stack['StackStatus']
                result['by_status'][status] = result['by_status'].get(status, 0) + 1
                
                result['details'].append({
                    'name': stack['StackName'],
                    'status': status,
                    'created': stack['CreationTime'].isoformat()
                })
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ CloudFormation audit error: {e}")
            return {'error': str(e)}
    
    def audit_api_gateway(self) -> Dict[str, Any]:
        """API Gateway audit"""
        print("  → API Gateway APIs...")
        
        try:
            apis = self.api_gateway.get_rest_apis()
            result = {
                'total': len(apis['items']),
                'details': []
            }
            
            for api in apis['items']:
                result['details'].append({
                    'id': api['id'],
                    'name': api['name'],
                    'created': api['createdDate'].isoformat(),
                    'endpoint_type': api.get('endpointConfiguration', {}).get('types', ['EDGE'])[0]
                })
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ API Gateway audit error: {e}")
            return {'error': str(e)}
    
    def audit_code_services(self) -> Dict[str, Any]:
        """Audit Code services"""
        print("  → CodeBuild, CodePipeline, CodeDeploy...")
        try:
            result = {
                'codebuild': {'projects': 0},
                'codepipeline': {'pipelines': 0},
                'codedeploy': {'applications': 0}
            }
            
            # CodeBuild
            try:
                codebuild_projects = self.codebuild.list_projects()
                result['codebuild']['projects'] = len(codebuild_projects.get('projects', []))
            except:
                pass
            
            # CodePipeline
            try:
                codepipeline_pipelines = self.codepipeline.list_pipelines()
                result['codepipeline']['pipelines'] = len(codepipeline_pipelines.get('pipelines', []))
            except:
                pass
            
            # CodeDeploy
            try:
                codedeploy_apps = self.codedeploy.list_applications()
                result['codedeploy']['applications'] = len(codedeploy_apps.get('applications', []))
            except:
                pass
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ Code services audit error: {e}")
            return {'error': str(e)}
    
    # ==================== MESSAGING SERVICES ====================
    
    def audit_sns_topics(self) -> Dict[str, Any]:
        """SNS topics audit"""
        print("  → SNS Topics...")
        
        try:
            topics = self.sns.list_topics()
            result = {
                'total': len(topics['Topics']),
                'details': []
            }
            
            for topic in topics['Topics']:
                topic_arn = topic['TopicArn']
                result['details'].append({
                    'arn': topic_arn,
                    'name': topic_arn.split(':')[-1]
                })
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ SNS audit error: {e}")
            return {'error': str(e)}
    
    def audit_sqs_queues(self) -> Dict[str, Any]:
        """SQS queues audit"""
        print("  → SQS Queues...")
        
        try:
            queues = self.sqs.list_queues()
            result = {
                'total': len(queues.get('QueueUrls', [])),
                'details': []
            }
            
            for queue_url in queues.get('QueueUrls', []):
                queue_name = queue_url.split('/')[-1]
                result['details'].append({
                    'url': queue_url,
                    'name': queue_name
                })
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ SQS audit error: {e}")
            return {'error': str(e)}
    
    def audit_eventbridge(self) -> Dict[str, Any]:
        """Audit EventBridge"""
        print("  → EventBridge Rules...")
        try:
            response = self.eventbridge.list_rules()
            result = {
                'rules': len(response.get('Rules', [])),
                'event_buses': 0,
                'details': []
            }
            
            for rule in response.get('Rules', []):
                rule_info = {
                    'name': rule.get('Name', 'Unknown'),
                    'state': rule.get('State', 'ENABLED')
                }
                result['details'].append(rule_info)
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ EventBridge audit error: {e}")
            return {'error': str(e)}
    
    # ==================== ANALYTICS & MANAGEMENT ====================
    
    def analyze_costs(self) -> Dict[str, Any]:
        """Basic cost analysis"""
        print("  → Cost Analysis...")
        
        try:
            result = {
                'estimated_monthly_cost': 0,
                'potential_savings': 0,
                'top_cost_centers': []
            }
            
            # Calculate estimated savings from findings
            for finding in self.findings:
                result['potential_savings'] += finding.estimated_savings
            
            return result
            
        except Exception as e:
            print(f"    ⚠️ Cost analysis error: {e}")
            return {'error': str(e)}
    
    def check_compliance(self) -> Dict[str, Any]:
        """Basic compliance checks"""
        print("  → Compliance Checks...")
        
        result = {
            'checks': [],
            'passed': 0,
            'failed': 0
        }
        
        # Define compliance checks
        compliance_checks = [
            {
                'id': 'MFA_ENABLED',
                'description': 'Root user has MFA enabled',
                'severity': 'CRITICAL'
            },
            {
                'id': 'S3_ENCRYPTION',
                'description': 'S3 buckets have encryption enabled',
                'severity': 'HIGH'
            },
            {
                'id': 'PUBLIC_ACCESS_BLOCKED',
                'description': 'S3 public access is blocked',
                'severity': 'HIGH'
            },
            {
                'id': 'OLD_ACCESS_KEYS',
                'description': 'No access keys older than 90 days',
                'severity': 'MEDIUM'
            }
        ]
        
        result['checks'] = compliance_checks
        
        return result
    
    # ==================== HELPER METHODS ====================
    
    def _generate_summary(self, services: Dict[str, Any]) -> Dict[str, Any]:
        """Generate audit summary"""
        total_resources = 0
        total_findings = len(self.findings)
        estimated_savings = 0
        
        # Count critical/high findings
        critical_findings = len([f for f in self.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
        
        # Calculate estimated savings
        for finding in self.findings:
            estimated_savings += finding.estimated_savings
        
        return {
            'total_resources_audited': len(services),
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'estimated_monthly_savings': estimated_savings,
            'audit_duration': 'N/A',
            'services_with_issues': len([s for s in services.values() if 'error' not in s])
        }
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Group findings by type
        finding_types = {}
        for finding in self.findings:
            f_type = finding.resource_type.value
            if f_type not in finding_types:
                finding_types[f_type] = []
            finding_types[f_type].append(finding)
        
        # Create recommendations for each type
        for resource_type, findings in finding_types.items():
            if findings:
                rec = {
                    'resource_type': resource_type,
                    'total_issues': len(findings),
                    'critical_issues': len([f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]),
                    'estimated_savings': sum(f.estimated_savings for f in findings),
                    'actions': []
                }
                
                # Add specific actions
                if resource_type == 'EC2':
                    rec['actions'].append('Review and terminate idle instances')
                    rec['actions'].append('Release unattached Elastic IPs')
                elif resource_type == 'S3':
                    rec['actions'].append('Enable encryption on buckets')
                    rec['actions'].append('Review public access settings')
                elif resource_type == 'IAM':
                    rec['actions'].append('Enable MFA for all users')
                    rec['actions'].append('Rotate old access keys')
                elif resource_type == 'RDS':
                    rec['actions'].append('Review publicly accessible databases')
                
                recommendations.append(rec)
        
        return recommendations
    
    def _generate_demo_report(self) -> Dict[str, Any]:
        """Generate demo report for testing"""
        print("📋 Generating demo report...")
        
        return {
            'metadata': {
                'account_id': '123456789012',
                'region': self.region,
                'audit_timestamp': datetime.now(timezone.utc).isoformat(),
                'demo_mode': True
            },
            'summary': {
                'total_resources_audited': 15,
                'total_findings': 8,
                'critical_findings': 3,
                'estimated_monthly_savings': 245.75,
                'audit_duration': '00:02:30'
            },
            'findings': [
                {
                    'resource_type': 'EC2',
                    'resource_id': 'i-0123456789abcdef0',
                    'finding': 'Unattached EBS volume',
                    'severity': 'HIGH',
                    'description': '50GB volume not attached to any instance',
                    'recommendation': 'Delete if not needed',
                    'estimated_savings': 15.0,
                    'region': self.region
                },
                {
                    'resource_type': 'IAM',
                    'resource_id': 'john.doe',
                    'finding': 'User without MFA',
                    'severity': 'CRITICAL',
                    'description': 'IAM user without multi-factor authentication',
                    'recommendation': 'Enable MFA immediately',
                    'estimated_savings': 0.0,
                    'region': self.region
                }
            ],
            'recommendations': [
                {
                    'resource_type': 'EC2',
                    'total_issues': 3,
                    'critical_issues': 2,
                    'estimated_savings': 45.50,
                    'actions': ['Terminate idle instances', 'Release Elastic IPs']
                },
                {
                    'resource_type': 'S3',
                    'total_issues': 2,
                    'critical_issues': 1,
                    'estimated_savings': 0.0,
                    'actions': ['Enable bucket encryption', 'Review public access']
                }
            ]
        }
    
    def export_report(self, report: Dict[str, Any], format: str = 'json') -> str:
        """
        Export audit report in various formats
        
        Args:
            report: Audit report
            format: Export format (json, csv, html, txt)
        
        Returns:
            File path of exported report
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"aws_audit_report_{timestamp}.{format}"
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        elif format == 'csv':
            # Export findings to CSV
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Severity', 'Resource Type', 'Resource ID', 'Finding', 'Recommendation', 'Estimated Savings'])
                
                for finding in report.get('findings', []):
                    writer.writerow([
                        finding.get('severity', ''),
                        finding.get('resource_type', ''),
                        finding.get('resource_id', ''),
                        finding.get('finding', ''),
                        finding.get('recommendation', ''),
                        finding.get('estimated_savings', 0)
                    ])
        
        elif format == 'txt':
            with open(filename, 'w') as f:
                f.write(f"AWS Audit Report\n")
                f.write(f"================\n\n")
                f.write(f"Account: {report['metadata']['account_id']}\n")
                f.write(f"Region: {report['metadata']['region']}\n")
                f.write(f"Timestamp: {report['metadata']['audit_timestamp']}\n\n")
                
                f.write(f"SUMMARY\n")
                f.write(f"-------\n")
                f.write(f"Total Findings: {report['summary']['total_findings']}\n")
                f.write(f"Critical Findings: {report['summary']['critical_findings']}\n")
                f.write(f"Estimated Savings: ${report['summary']['estimated_monthly_savings']:.2f}/month\n\n")
                
                f.write(f"FINDINGS\n")
                f.write(f"--------\n")
                for finding in report.get('findings', [])[:10]:  # First 10 findings
                    f.write(f"[{finding.get('severity')}] {finding.get('resource_type')}/{finding.get('resource_id')}\n")
                    f.write(f"  {finding.get('finding')}\n")
                    f.write(f"  Recommendation: {finding.get('recommendation')}\n\n")
        
        print(f"✅ Report exported to: {filename}")
        return filename


# ==================== MAIN EXECUTION ====================

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Comprehensive Resource Auditor')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--format', choices=['json', 'csv', 'txt', 'all'], default='json', 
                       help='Output format')
    parser.add_argument('--quick', action='store_true', help='Quick audit (limited services)')
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                AWS COMPREHENSIVE AUDITOR v2.1                ║
    ║         Cost Optimization • Security • Compliance            ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize auditor
    auditor = AWSComprehensiveAuditor(region=args.region, profile=args.profile)
    
    # Run audit
    if args.quick:
        print("\n⚡ Running QUICK audit...")
        # Run limited audit
        report = {
            'metadata': {
                'account_id': auditor.account_id if hasattr(auditor, 'account_id') else 'demo',
                'region': args.region,
                'audit_timestamp': datetime.now(timezone.utc).isoformat(),
                'mode': 'quick'
            },
            'summary': {},
            'findings': []
        }
    else:
        report = auditor.run_complete_audit()
    
    # Export report
    if args.format == 'all':
        for fmt in ['json', 'csv', 'txt']:
            auditor.export_report(report, fmt)
    else:
        auditor.export_report(report, args.format)
    
    # Print summary to console
    print("\n" + "="*60)
    print("📊 AUDIT SUMMARY")
    print("="*60)
    
    if 'summary' in report:
        summary = report['summary']
        print(f"Total Resources Audited: {summary.get('total_resources_audited', 'N/A')}")
        print(f"Total Findings: {summary.get('total_findings', 0)}")
        print(f"Critical Findings: {summary.get('critical_findings', 0)}")
        print(f"Estimated Monthly Savings: ${summary.get('estimated_monthly_savings', 0):.2f}")
    
    print(f"\n🔍 Top Recommendations:")
    for rec in report.get('recommendations', [])[:3]:
        print(f"  • {rec['resource_type']}: {rec['total_issues']} issues (${rec['estimated_savings']:.2f} savings)")
    
    print("\n✅ Audit completed. Check exported report for details.")


if __name__ == "__main__":
    main()