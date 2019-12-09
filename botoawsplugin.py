#!/usr/bin/env python3


def main(argv):
    action = argv[1]
    if len(argv) > 2:
        args = argv[2:]
    else:
        args = []
    #print(f"[INFO] Action: {action}")
    #print(f"Arguments: {args}")
    response = operation(action, args)

def help(*args):
    if len(args) == 0:
        print("Usage:")
        print("Available options\n")
        operations = ["createinstance","createkeypair","deletekeypair","describeinstance","getinstance","createsecuritygroup","terminateinstance","getallinstances", "benchmark", "getlogs"]
        for op in operations:
            print(f"{__file__} {op}")
        exit(1)
    else: 
        str = ""
        for arg in args:
            str += "<"+arg+"> "
        print(f"Usage: {__file__} {str}")
        exit(1)

def operation(action, args):
    response = None
    ec2 = boto3.client('ec2')
    #for instance in ec2.instances.all():
        #print(instance.id, instance.state)
    if action == "createkeypair":
        if len(args) == 0:
            help(action, "keypairname")
        response = create_keypair(args[0])
    elif action == "deletekeypair":
        if len(args) == 0:
            help(action, "keypairname")
        response = delete_keypair(args[0])
    elif action == "createinstance":
        if len(args) == 0:
            help(action, "config_file_path(default: instance_template.json)")
        response = create_instance(args[0])
    elif action == "getinstance":
        if len(args) == 0:
            help(action, "instance_id")
        response = get_instance(args[0])
    elif action == "describeinstance":
        if len(args) == 0:
            help(action, "instance_id")
        response = describe_instance(args[0])
    elif action == "getvpc":
        response = get_default_vpc()
    elif action == "createsecuritygroup":
        if len(args) == 0:
            help(action, "config_json_file_path")
        response = create_security_group(args[0])
    elif action == "getallinstances":
        response = get_all_instances()
    elif action == "terminateinstance":
        if len(args) == 0:
            help(action, "instance_id")
        response = terminate_instance(args[0])
    elif action == "benchmark":
        if len(args) == 0:
            help(action, "instance_id")
        response = benchmark(args[0])
    elif action == "getlogs":
        if len(args) == 0:
            help(action, "instance_id")
        response = get_logs(args[0])
    else:
        print(f"[ERROR] Invalid action: <{action}>")
        help()
    return response

def get_instance(*args, display=True):
    
    attributes_map = {}
    ec2_resource = boto3.resource("ec2")
    instance = ec2_resource.Instance(args[0])

    if display: 
        table = PrettyTable()
        table.field_names = ["Instance ID","Public IP", "DNS Name", "Key Name", "State"]
        table.add_row([instance.id, instance.public_ip_address, instance.public_dns_name, instance.key_name, instance.state['Name']])
        print(table)
    
    attributes_map['public_ip_address'] = instance.public_ip_address
    attributes_map['key_name'] = instance.key_name
    attributes_map['state'] = instance.state['Name']
    return attributes_map

def get_all_instances():
    instances = []
    ec2_client = boto3.client("ec2")
    response = ec2_client.describe_instances()

    table = PrettyTable()
    table.field_names = ["Instance Id", "Public IP", "DNS Name", "Key Name", "State"]
    
    

    for res in response['Reservations']:
        #print(res['Instances'][0]['InstanceId'])
        ins = res['Instances'][0]
        #print(type(ins))
        table.add_row([res['Instances'][0]['InstanceId'], ins.get('PublicIpAddress'), ins.get('PublicDnsName'), res['Instances'][0]['KeyName'], res['Instances'][0]['State']['Name']])
        instances.append((res['Instances'][0]['InstanceId'],res['Instances'][0]['State']['Name']))
    print(table)
    #print(instances)
    return instances

def terminate_instance(*args):
    ec2_resource = boto3.resource("ec2")
    instance = ec2_resource.Instance(args[0])
    response = instance.terminate()
    print(f"[INFO] Initiated termination of instance")
    print(f"[INFO] Status from API: {response['ResponseMetadata']['HTTPStatusCode']}")
    state = "running"
    while state != "terminated":
        print(f"[INFO] Waiting for instance to terminate")
        time.sleep(5)
        res = get_instance(args[0], display=False)
        state = res['state']
    get_instance(args[0])    
    return response

def describe_instance(*args):
    ec2_client = boto3.client("ec2")
    response = ec2_client.describe_instances(InstanceIds=[args[0]])
    file_name = args[0]+'_details.json'
    #print(response)
    f = open(file_name,'w',encoding='utf-8')
    f.write(json.dumps(response, default=str))
    f.close()
    print(f"[INFO] Details written to {file_name}")
   
    
def create_keypair(keypairname="cloudinfra_key"):
    try: 
        ec2_client = boto3.client("ec2")
        private_key_file_name = keypairname+".pem"
        response = ec2_client.create_key_pair(KeyName=keypairname)
        status = response['ResponseMetadata']['HTTPStatusCode']
        print(f"[INFO] Status code: {status}")
        if status == 200:
            private_key = response['KeyMaterial']
            f = open(private_key_file_name,"w")
            f.write(private_key)
            f.close()
            print(f"[INFO] Private Key written to : {os.path.abspath('.')+'/'+private_key_file_name}")
        return response
    except ClientError as ex:
        print(f"[ERROR] {ex}")

def delete_keypair(keypairname="cloudinfra_key"):
    private_key_file_name = keypairname+".pem"
    try: 
        ec2_client = boto3.client("ec2")
        response = ec2_client.delete_key_pair(KeyName=keypairname)
        #print(response)
        status = response['ResponseMetadata']['HTTPStatusCode']
        print(f"[INFO] Status code: {status}")
        if status == 200 and os.path.isfile(private_key_file_name):
            print(f"[INFO] Deleting private key {private_key_file_name}")
            os.remove(private_key_file_name)
        else:
            print("[INFO] Nothing to delete")
        return response
    except ClientError as ex:
        print(f"[ERROR] {ex}")

def get_default_vpc():
     ec2_resource = boto3.resource("ec2")
     vpcs = ec2_resource.vpcs.all()
     for vpc in vpcs:
        if vpc.is_default:
            print(f"[INFO] Default vpc ID: {vpc.id}")
            return vpc.id

def create_security_group(*args):
    security_group_names = find_sg_by_vpc_id()
    #template_file = 'security_groups_template.json'
    try:
        sg_template = open(args[0],'r').read()
    except FileNotFoundError:
        print(f"[ERROR] Security Group Config file path is not valid: {args[0]}")
        return
    sg_template = json.loads(sg_template)
    sg_name = sg_template.get('GroupName')
    if sg_name not in security_group_names:
        
        vpc_id = get_default_vpc()
        resource = boto3.resource('ec2')
        ingress_rules = sg_template.get('IngressRules')
        
        security_group = resource.create_security_group(Description=sg_template.get('Description'), GroupName=sg_template.get('GroupName'),VpcId=vpc_id)
        for ing in ingress_rules:
            #print(ing['IpRanges'][0]['Description'])
            security_group.authorize_ingress(
                CidrIp=ing['IpRanges'][0]['CidrIp'],
                IpProtocol=ing.get('IpProtocol'),
                FromPort=ing.get('FromPort'),
                ToPort=ing.get('ToPort')
            )
        print(f"[INFO] Security group: '{sg_name}' added")
        return security_group.group_name
    else:
        print(f"[INFO] Security Group: '{sg_name}' already present")
        return sg_name

def find_sg_by_vpc_id():
    security_group_names = []
    client = boto3.client('ec2')
    vpc_id = get_default_vpc()
    response = client.describe_security_groups(Filters=[{"Name":"vpc-id","Values":[vpc_id]}])
    for sg in response['SecurityGroups']:
        #print(sg['GroupName'])
        security_group_names.append(sg['GroupName'])
    f = open('security_groups.json', 'w')
    f.write(json.dumps(response))
    f.close()
    return security_group_names

def create_instance(*args):
    ami_dict = {
        "ubuntu":"ami-04b9e92b5572fa0d1",
        "rhel":"ami-0c322300a1dd5dc79",
        "centos":"ami-6552950e",
        "amazonlinux":"ami-00dc79254d0461090"
    }
    #print(args)
    instance_id = None
    try:
        f = open(args[0],"r").read()
    except FileNotFoundError as ex:
        print(f"[ERROR] File path {args[0]} not valid!!")
        return None
    instance_properties = json.loads(f)
    #print(type(instance_properties))
    print(f"[INFO] Creating an instance")
    try:
        ec2_resource = boto3.resource("ec2",region_name=instance_properties.get("Region"))
        security_group = create_security_group(instance_properties.get('SecurityGroupConfigFile'))
        instances = ec2_resource.create_instances(
            ImageId=instance_properties.get('ImageId'), 
            MinCount=instance_properties.get('MinCount'), 
            MaxCount=instance_properties.get('MaxCount'),
            KeyName=instance_properties.get('KeyName'),
            InstanceType=instance_properties.get('InstanceType'),
            SecurityGroups=[security_group]
        )
        instances[0].wait_until_running()
        instance = instances[0]
        instance_id = instance.id
        response = get_instance(instance_id)

        print(f"\n[INFO] Use the below command to ssh to the AWS Instance")
        print(f"\tssh -i {response['key_name']}.pem -o \"StrictHostKeyChecking no\"  ubuntu@{response['public_ip_address']}\n")
        #print(instances[0])
        #print(f"[INFO] Instance ID: {instance.id}")
        #print(f"[INFO] Public IP Address: {instance.public_ip_address}")
        #print(f"[INFO] Public DNS Name: {instance.public_dns_name}")
        #print(f"[INFO] Key Name: {instance.key_name}")
        #print(f"[INFO] Security Groups: {instance.security_groups}")
        #print(f"[INFO] State: {instance.state['Name']}")
        

    except ClientError as ex:
        print(f"[ERROR] {ex}")
    except KeyError as ex:
        print(f"[ERROR] {ex}")
    return instance_id

def get_logs(*args):
    instanceid = args[0]
    instance = get_instance(instanceid, display=False)
    if instance:
        instance['output_path'] = 'blast_log.txt'
        instance['username'] = 'ubuntu'
        instance['logfile_path'] = 'blast_example/results.txt'
        file_loader = FileSystemLoader('templates')
        env = Environment(loader=file_loader)
        template_file = "remote_scp_logs.sh.template"
        template = env.get_template(template_file)
        output = template.render(inputs=instance)
        temp = template_file.split('.')
        output_file = '.'.join(temp[:len(temp)-1])
        f = open(output_file,'w')
        f.write(output)
        f.close()
        os.chmod(output_file,mode=stat.S_IRWXU)
        res = subprocess.run([f'./{output_file}'], cwd=os.getcwd())
        
        # Return code is non-zero in case of error
        if not res.returncode:
            print(f"[INFO] Log file written to {os.getcwd()}/{instance['output_path']}")
        else:
            print(f"[ERROR] Error in fetching log file!!")
    else:
        print(f"[ERROR] No instance found with instance ID = {instance_id}")
        return  

def benchmark(*args):
    instanceid = args[0]
    instance = get_instance(instanceid, display=False)
    if instance:
        instance['script_name'] = 'bootstrap.sh'
        instance['username'] = 'ubuntu'
        file_loader = FileSystemLoader('templates')
        env = Environment(loader=file_loader)
        template_file = "remote_ssh.sh.template"
        template = env.get_template(template_file)
        output = template.render(inputs=instance)
        temp = template_file.split('.')
        output_file = '.'.join(temp[:len(temp)-1])
        f = open(output_file,'w')
        f.write(output)
        f.close()
        os.chmod(output_file,mode=stat.S_IRWXU)
        subprocess.run([f'./{output_file}'], cwd=os.getcwd())
    else:
        print(f"[ERROR] No instance found with instance ID = {instance_id}")
        return

if __name__ == "__main__":
    try:
        import boto3
        import xmltodict
        import sys
        import os.path
        import os
        import stat
        import json
        import subprocess
        import time
        from botocore.exceptions import ClientError
        from jinja2 import Template, FileSystemLoader, Environment
        from prettytable import PrettyTable
    except ModuleNotFoundError as ex:
        print(f"[ERROR] {ex}")
        exit(1)
    if len(sys.argv) < 2:
        help()
    
    main(sys.argv)
   
