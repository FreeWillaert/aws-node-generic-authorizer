interface IAuthorizerResponse {
    principalId: string;
    policyDocument: {
        Version: string;
        Statement: [
            {
                Action: string;
                Effect: string;
                Resource: string;
            }
        ]
    },
    context: {
        [key: string] : string;
    },
    usageIdentifierKey?: string;
}