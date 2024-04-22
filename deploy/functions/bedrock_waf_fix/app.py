import os
import json
import boto3
import instruction

def lambda_handler(event, context):
    session = boto3.Session(
        profile_name=os.environ.get("BWB_PROFILE_NAME")
    )   # sets the profile name to use for AWS credentials

    bedrock = session.client(
        service_name='bedrock-runtime',  # creates a Bedrock client
        region_name=os.environ.get("BWB_REGION_NAME"),
        endpoint_url=os.environ.get("BWB_ENDPOINT_URL")
    )
    
    bedrock_model_id = "anthropic.claude-3-sonnet-20240229-v1:0"  # set the foundation model
    
    prompt = instruction.instruction + event.get('body') #instruction + exploit
    print(prompt)
    json_data ={
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            }
                        ]
                    }
                ],
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 20000,
                "temperature": 0,
                "top_k": 250,
                "top_p": 0.999,
                "stop_sequences": [
                    "nnHuman:"
                ]
            }

    body = json.dumps(json_data)  # build the request payload
    
    response = bedrock.invoke_model(body=body, modelId=bedrock_model_id,accept='application/json', contentType='application/json')  # send the payload to Bedrock

    #print(response)

    response_body = json.loads(response.get('body').read())  # read the response

    response_text = response_body.get("content")[0].get("text")  # extract the text from the JSON response
    
    loop = {"loop":event.get('loop')}
    response = json.loads(response_text)
    result = {**response,**loop}
    
    return result