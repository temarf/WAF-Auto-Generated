const { StepFunctionsClient } = require("@aws-sdk/client-sfn");
const stepfunctions = new StepFunctionsClient();

var redirectToStepFunctions = function(lambdaArn, statemachineName, executionName, callback) {
  const email = process.env.email || 'unknown';
  const lambdaArnTokens = lambdaArn.split(":");
  const partition = lambdaArnTokens[1];
  const region = lambdaArnTokens[3];
  const accountId = lambdaArnTokens[4];

  console.log("partition=" + partition);
  console.log("region=" + region);
  console.log("accountId=" + accountId);

  const executionArn = "arn:" + partition + ":states:" + region + ":" + accountId + ":execution:" + statemachineName + ":" + executionName;
  console.log("executionArn=" + executionArn);

  const url = "https://console.aws.amazon.com/states/home?region=" + region + "#/executions/details/" + executionArn;
  callback(null, {
      statusCode: 302,
      headers: {
        Location: url
      }
  });
};

exports.handler = async (event, context, callback) => {
  console.log('Event= ' + JSON.stringify(event));
  const action = event.query.action;
  const taskToken = event.query.taskToken;
  const statemachineName = event.query.sm;
  const executionName = event.query.ex;

  var message = "";

  if (action === "approve") {
    message = { "Status": `Approved! Task approved by ${process.env.email || 'unknown'}` };
  } else if (action === "reject") {
    message = { "Status": `Rejected! Task rejected by ${process.env.email || 'unknown'}` };
  } else {
    console.error("Unrecognized action. Expected: approve, reject.");
    callback(new Error("Failed to process the request. Unrecognized Action."));
    return;
  }

  try {
    const data = await stepfunctions.sendTaskSuccess({
      output: JSON.stringify(message),
      taskToken: event.query.taskToken
    });
    redirectToStepFunctions(context.invokedFunctionArn, statemachineName, executionName, callback);
  } catch (err) {
    console.error(err, err.stack);
    callback(err);
  }
};