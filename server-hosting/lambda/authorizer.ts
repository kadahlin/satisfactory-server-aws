import { AuthCreds } from "./auth-creds";

// Lambda authorizer for basic authentication
export const handler = async (event: any) => {
  const authHeader = event.headers?.Authorization || "";
  const encodedCreds = authHeader.split(" ")[1] || "";
  const [username, password] = Buffer.from(encodedCreds, "base64")
    .toString()
    .split(":");

  if (username === AuthCreds.username && password === AuthCreds.password) {
    return generateAllow(event.methodArn);
  } else {
    return generateDeny(event.methodArn);
  }
};

// Helper functions to generate allow/deny responses
const generateAllow = (methodArn: string) => ({
  principalId: "user",
  policyDocument: {
    Version: "2012-10-17",
    Statement: [
      { Action: "execute-api:Invoke", Effect: "Allow", Resource: methodArn },
    ],
  },
});

const generateDeny = (methodArn: string) => ({
  principalId: "user",
  policyDocument: {
    Version: "2012-10-17",
    Statement: [
      { Action: "execute-api:Invoke", Effect: "Deny", Resource: methodArn },
    ],
  },
});
