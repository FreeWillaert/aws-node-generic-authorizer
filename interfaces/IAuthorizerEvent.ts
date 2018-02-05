interface IAuthorizerEvent {
    type: string;
    authorizationToken?: string;
    headers?: {
        [key: string]: string;
    },
    methodArn: string;
}