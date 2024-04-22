import boto3
from botocore.exceptions import ClientError
from urllib.parse import quote
import json
import os

def lambda_handler(event, context):
    """
    Lambda function to send an approval email for WAF rules.
    """
    region = os.environ.get('AWS_REGION')
    email = os.environ.get('Email')
    # Log the event and context
    print(f"Event: {event}")
    print(f"Context: {context}")

    # Extract data from the event
    execution_context = event.get("ExecutionContext")
    execution_name = execution_context.get("Execution", {}).get("Name")
    state_machine_name = execution_context.get("StateMachine", {}).get("Name")
    task_token = execution_context.get("Task", {}).get("Token")
    api_gateway_endpoint = event.get("APIGatewayEndpoint")

    # Construct the approve and reject endpoints
    approve_endpoint = f"{api_gateway_endpoint}/execution?action=approve&ex={execution_name}&sm={state_machine_name}&taskToken={quote(task_token)}"
    reject_endpoint = f"{api_gateway_endpoint}/execution?action=reject&ex={execution_name}&sm={state_machine_name}&taskToken={quote(task_token)}"

    # Print the endpoints for debugging
    print(f'approveEndpoint= {approve_endpoint}')
    print(f'rejectEndpoint= {reject_endpoint}')

    # Construct the email message (with HTML formatting and styling)
    email_message = """
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                font-size: 14px;
                color: #333333;
            }}
            h1 {{
                color: #0072C6;
            }}
            .section {{
                margin-bottom: 20px;
            }}
            .section-title {{
                font-weight: bold;
                color: #0072C6;
            }}
            .button {{
                display: inline-block;
                padding: 10px 20px;
                background-color: #0072C6;
                color: #FFFFFF;
                text-decoration: none;
                border-radius: 4px;
            }}
            pre {{
                background-color: #f0f0f0;
                padding: 10px;
                font-family: monospace;
                white-space: pre-wrap;
            }}
        </style>
    </head>
    <body>
        <h1>New CVE Proof of Concept</h1>
        <p>Hello!</p>
        <p>This is an email requiring an approval for WAF rules approval.</p>
        <p>Please check the following information and click the "Approve" link if you want to apply the rules.</p>
        <div class="section">
            <span class="section-title">Execution Name:</span> {execution_name}
        </div>
        <div class="section">
            <span class="section-title">Rules:</span><br>
            <pre>{rules_json}</pre>
        </div>
        <div class="section">
            <span class="section-title">Description:</span><br>
            {description}
        </div>
        <div class="section">
            <span class="section-title">Sample Command:</span><br>
            {command} <br><br>
            <span style="color: red;">This is a sample command. Use it with consideration, as the command might not be 100% accurate.</span>
        </div>
        <a class="button" href="{approve_endpoint}">Approve</a>
        <a class="button" href="{reject_endpoint}">Reject</a>
        <p>Thanks for using WAF Auto Generation!</p>
    </body>
    </html>
    """

    # Load the rules JSON and description
    rules_json = json.dumps(event.get('rules', {}).get('Rules', ''), indent=4)
    description = "<br><br>".join(event.get("rules", {}).get("Description", []))
    command = "<br><br>".join(event.get("rules", {}).get("Command", ""))
    # Replace placeholders with actual values
    email_message = email_message.format(
        execution_name=execution_name,
        rules_json=rules_json,
        description=description,
        command=command,
        approve_endpoint=approve_endpoint,
        reject_endpoint=reject_endpoint
    )

    # Set up the SES client
    ses_client = boto3.client("ses", region_name="us-east-1")

    # Define the email parameters
    sender_email = email
    recipient_email = email
    subject = "Required approval from AWS Step Functions"

    # Send the email
    try:
        response = ses_client.send_email(
            Destination={
                "ToAddresses": [recipient_email],
            },
            Message={
                "Body": {
                    "Html": {
                        "Charset": "UTF-8",
                        "Data": email_message,
                    }
                },
                "Subject": {
                    "Charset": "UTF-8",
                    "Data": subject,
                },
            },
            Source=sender_email,
        )
        print(f"Email sent: {response['MessageId']}")
    except ClientError as e:
        print(f"Error sending email: {e.response['Error']['Message']}")
        raise e