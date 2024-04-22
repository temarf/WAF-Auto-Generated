import boto3
import requests
from botocore.exceptions import ClientError
import urllib.request
import os

ssm = boto3.client('ssm')
s3 = boto3.client('s3')
bucket_name = os.environ.get('BUCKET_NAME')


def lambda_handler(event, context):
    base_url = 'https://www.exploit-db.com/download/'
    download_number = get_param("cve") #current next cve code
    while True:
        download_url = f"{base_url}{download_number}" #this might change over time
        print(download_url)
        object_key = f"downloaded_files/Po{download_number}.ext" #object name
        try:
            curl = requests.get(download_url) #curl url doesn't matter what response its provided as long as it is not 404
            response = urllib.request.urlopen(download_url) #download the url
            response = response.read()
            try: #try download file to bucket
                s3.put_object(
                    Bucket=bucket_name,
                    Key=object_key,
                    Body=response
                )
                print(f"Downloaded file from {download_url} and uploaded to {bucket_name}/{object_key}")
                download_number = int(download_number)+1 #increment to next poc if file is successfully downloaded, need to covert into int to add
            except ClientError as e:
                print(f"Error uploading file to S3: {e}")
                break
        except Exception as e: #if response is 404 it considered as an error, will catch it on curl
            update_param("cve",str(download_number)) #update to the possible next number. need to convert back to str to store
            return(f"URL: {download_url}. Does not exist no more CVE for today.")

def get_param(name): #get parameter from ssm
    try:
        parameter = ssm.get_parameter(Name=name)
        return parameter["Parameter"]["Value"]
    
    except Exception as e:
        response = update_param(name,'51950')
        parameter = ssm.get_parameter(Name=name)
        return parameter["Parameter"]["Value"]

def update_param(name,value): #update the parameter in ssm (no need to keep it secret)
        response = ssm.put_parameter(
            Name=name,
            Value=value,
            Type='String',
            Overwrite=True,
        )
        return response