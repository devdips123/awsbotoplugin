#!/usr/bin/env python3
import boto3
import json

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

def get_default_vpc():
     ec2_resource = boto3.resource("ec2")
     vpcs = ec2_resource.vpcs.all()
     for vpc in vpcs:
        if vpc.is_default:
            print(f"[INFO] Default vpc ID: {vpc.id}")
            return vpc.id

def create_security_group():
    security_group_names = find_sg_by_vpc_id()
    sg_template = open('security_groups_template.json','r').read()
    sg_template = json.loads(sg_template)
    sg_name = sg_template.get('GroupName')
    if sg_name not in security_group_names:
        print(f"[INFO] Security group: '{sg_name}' not found. Will be created")
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
    else:
        print(f"[INFO] Security Group: '{sg_name}' already present")

def main():
    client = boto3.client('ec2')
    response = client.describe_instances()
    resource = boto3.resource('ec2')
    #describe_security_group()
    #create_security_group()
    #print(response)
    #response = json.loads(response)
    for res in response['Reservations']:
        print(res['Instances'][0]['InstanceId'])
    

def pandas_ex():
    df = pd.DataFrame({"x":[i for i in range(1,5)],"y":[i for i in range(1,5)]})
    print(df.to_string())
    
def run_shell():
    subprocess.run(['./helloworld.sh'])

def print_table():
    df = pd.DataFrame({"name":[i for i in range(1,5)],"age":[i for i in range(1,5)]})
    print(list(df.columns))
    print(df.head())
    

def generate_from_templates():
    inputs = {
        "name": "Debasish Sahoo",
        "age": "21"
    }
    file_loader = FileSystemLoader('templates')
    env = Environment(loader=file_loader)
    template_file = "test.txt.template"
    template = env.get_template(template_file)
    output = template.render(inputs=inputs)
    #print(output)
    temp = template_file.split('.')
    output_file = '.'.join(temp[:len(temp)-1])
    #print(output_file)
    f = open(output_file,'w')
    f.write(output)
    f.close()
if __name__ == "__main__":
    try:
        import pandas as pd
        import subprocess
        from jinja2 import Template, FileSystemLoader, Environment
    except ModuleNotFoundError as ex:
        print(ex)
    #main()
    #pandas_ex()
    run_shell()
    #generate_from_templates()
    #print_table()