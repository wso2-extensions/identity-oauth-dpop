# DPoP component

In traditional OAuth2 flows, presenting a valid Bearer token is proof enough to gain access to a protected resource. 
That means if a Bearer token gets into the hands of an unauthorized actor, they can impersonate the user and get 
unauthorized access to the protected resources. The resource server cannot validate the legitimacy of the sender and 
will grant access to whoever bears a valid token.A solution to this problem is to use sender-constrained tokens.

Demonstrating Proof of Possession (DPoP) is an application-level mechanism for sender-constraining OAuth access and 
refresh tokens. It enables a client to prove the possession of a public/private key pair by including a DPoP header in 
an HTTP request. The value of the header is a JSON Web Token (JWT) that enables the authorization server to bind issued 
tokens to the public part of a client's key pair. Recipients of such tokens are then able to verify the binding of the 
token to the key pair that the client has demonstrated that it holds via the DPoP header, thereby providing some 
assurance that the client presenting the token also possesses the private key. In other words, the legitimate presenter 
of the token is constrained to be the sender that holds and proves possession of the private part of the key pair.

## Specification 
https://datatracker.ietf.org/doc/html/rfc9449

## Design 

### Sequence Diagrams.
#### 1. DPoP bound authorization code request
![AuthzCodeBinding](https://github.com/wso2-extensions/identity-oauth-dpop/assets/110591829/807e5904-e230-458e-b7ba-4db48c829833)

#### 2. DPoP bound push authorization request
![Blank diagram - Page 2](https://github.com/wso2-extensions/identity-oauth-dpop/assets/110591829/cc696840-de86-4d9b-88dd-5e6d7f3bb12c)

#### 3. DPoP token request
![Screenshot from 2021-10-25 23-06-12](https://user-images.githubusercontent.com/26603378/138743329-5cc54271-08a6-44ec-938e-d675bdd24717.png)

#### 4. Invoking protected APIs with DPoP token and DPoP proof.
![Invoke API(2)](https://user-images.githubusercontent.com/26603378/138742776-3d2c2714-c87e-4f77-9dce-24fde3df600e.jpeg)

### Sample client application to create dpop proof
PR : [wso2 /samples-is#302 ](https://github.com/wso2/samples-is/pull/302 )

### Deployment Instructions

1. Build the project using mvn clean install.
2. Add the org.wso2.carbon.identity.oauth2.dpop-1.X.X-SNAPSHOT.jar JAR into the <IS_HOME>/repository/components/dropins folder.
3. Add the below configuration to <IS_HOME>/repository/conf/deployment.toml file.

 ```
[[event_listener]]
id = "dpop_listener"
type = "org.wso2.carbon.identity.core.handler.AbstractIdentityHandler"
name="org.wso2.carbon.identity.oauth2.dpop.listener.OauthDPoPInterceptorHandlerProxy"
order = 13
enable = true
properties.header_validity_period = 90
properties.skip_dpop_validation_in_revoke = "true"

[[event_handler]]
name= "dpopEventHandler"
subscriptions =["POST_ISSUE_CODE","PRE_HANDLE_PAR_REQUEST"]

[[oauth.custom_token_validator]]
type = "dpop"
class = "org.wso2.carbon.identity.oauth2.dpop.validators.DPoPTokenValidator"
```
4. Restart the Identity Server.
5. Sign in to the Management Console.
6. Navigate to the `Applications` section & select the application you want to configure DPoP.
7. In the application configurations page, navigate to the `Protocol` tab.
8. Scroll down to the `Token binding type` section & select `DPoP` from the options.

![Screenshot from 2024-05-10 15-44-50](https://github.com/wso2-extensions/identity-oauth-dpop/assets/110591829/3ea21c9f-2a88-429a-a463-b3c3f451981f)

### Sample Usage Instructions

#### 1. DPoP bound Authorization Code Request :

```
curl --location --request GET 'https://localhost:9443/oauth2/authorize? \
response_type=code \
&client_id=T3fCPO8eV0sR3wX9Yf14X38v0Eka \
&redirect_uri=https%3A%2F%2Foauth.pstmn.io%2Fv1%2Fcallback \
&dpop_jkt=C07a9MZgz5wYywPc39Tw81gE8QzhkpC14sjx-2pAwbI'
```
The additional authorization request parameter `dpop_jkt` is used to bind the issued authorization code to the client's proof-of-possession key.
This binding will enable end-to-end binding of the entire authorization flow.

Including this parameter in authorization request is **OPTIONAL** .If not included, the authorization code will not be 
bound to the client's proof-of-possession key. 

#### 2. DPoP bound Push Authorization Request :

```
curl --location --request POST 'https://localhost:9443/oauth2/par' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'dpop: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLTZGNGlydjc2andTaUxIZWJWemtzTGZqdFhZcGxTOVJ3bXZKRmRScC1yYyIsInkiOiJHYlZDRzBDM0xIQjlVbzdDSW9KZUIydk5BaHRlR05EcUh3VmNNRXV5QUkwIn19.eyJodG0iOiJQT1NUIiwic3ViIjoic3ViIiwibmJmIjoxNzE1NjY3MzUyLCJpc3MiOiJpc3N1ZXIiLCJodHUiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvcGFyIiwiaWF0IjoxNzE1NjY3MzUyLCJqdGkiOiI1ZjFjZWM4ZS1iM2I0LTQ3YTctOGE0NC1lNDc5NWUxNmJiZWUifQ.ltp0hesGvn1YYYPs3RpeaWaoe7cgXzZHNrFmllPGsUO3AH_cG4lMzt1iXz7VlWZtTPgAy9-WeOpdyZ8os-1PKQ' \
--data-urlencode 'response_type=code' \
--data-urlencode 'client_id=T3fCPO8eV0sR3wX9Yf14X38v0Eka' \
--data-urlencode 'redirect_uri=https://oauth.pstmn.io/v1/callback' \
--data-urlencode 'dpop_jkt=C07a9MZgz5wYywPc39Tw81gE8QzhkpC14sjx-2pAwbI'
```
When Pushed Authorization Requests (PAR) are used in conjunction with DPoP, there are two ways in which the DPoP key can
be communicated in the PAR request:

- Including the `dpop_jkt` parameter alongside other authorization request parameters in the POST body of the PAR 
request.
- Including the `DPoP` header in the PAR request.

One of the above methods is sufficient to bind the issued authorization code to the client's proof-of-possession key.

If both mechanisms are used at the same time, the authorization server will reject the request if the JWK Thumbprint in 
dpop_jkt does not match the public key in the DPoP header.

Similar to the authorization code request, including the `dpop_jkt` parameter or DPoP header in the PAR request is 
**OPTIONAL**. If not included, the authorization code will not be bound to the client's proof-of-possession key.

#### 3. Access Token from Password :

```
curl --location --request POST 'https://localhost:9443/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'dpop: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLTZGNGlydjc2andTaUxIZWJWemtzTGZqdFhZcGxTOVJ3bXZKRmRScC1yYyIsInkiOiJHYlZDRzBDM0xIQjlVbzdDSW9KZUIydk5BaHRlR05EcUh3VmNNRXV5QUkwIn19.eyJodG0iOiJQT1NUIiwic3ViIjoic3ViIiwibmJmIjoxNzE1NjY3NDU5LCJpc3MiOiJpc3N1ZXIiLCJodHUiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJpYXQiOjE3MTU2Njc0NTksImp0aSI6Ijc3NTBjMmQzLTRjNDMtNGY2Ny04MDM1LTEwNWE5YzRmNDgwZCJ9.B-DbYKd95ZKfOrBTHINOwIM-UW0bg8BPY6wWW07M9-jvX_Jm8lKAeCBrp0fDQe7su2vTl0Dcsgxw1OQVJG1eFw' \
--header 'Authorization: Basic ajdPOWVqbmpUSUN1VFl4cGMwamQ4MjJvU2FjYTpmREJzSXB5djlYS1lOVUxfQWs1QTM0NFh6cUVh' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=admin' \
--data-urlencode 'password=admin' \
--data-urlencode 'scope=openid internal_user_mgt_list'
```

&emsp;&ensp;Sample Response:

```
{
    "access_token": "1ce0fc0a-c830-307a-aafc-d25fdc4063ee",
    "refresh_token": "ff7a6adb-116d-3a6f-83ff-3f61c7fa8b2f",
    "scope": "internal_user_mgt_list openid",
    "id_token": "eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdSbE5qSmtPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZbU00WlRBM01XSTJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoiUGw2ZjJvdWNmY3RnQ2ZLazJZOEZ5USIsImF1ZCI6IjVEb09HWkFHQV9sQUdnSDB2WkJSRTgzTl9sQWEiLCJzdWIiOiJhZG1pbiIsIm5iZiI6MTY1Mjc2ODc5MiwiYXpwIjoiNURvT0daQUdBX2xBR2dIMHZaQlJFODNOX2xBYSIsImFtciI6WyJwYXNzd29yZCJdLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE2NTI3NzIzOTIsImlhdCI6MTY1Mjc2ODc5Mn0.dCwn5ln-iROxbVVOJicQFFqLse8NOYXc_HVnhCiQPoBLShaXKi-NbnTvXwoFL1NxQhv96YgyUhjrkLoQDEmzxQnFMkgq3hJV0MH68SBpsCaKIIzg3Z0KT_5VFSvDC-bQGHfmGS-Gxf5TWkKT7FGke-OYUw_x940qy_PMfZOM-q4A9gBiPTazjXbGo0dkIOINnEfz6TQvrE2opJxV7dj3bGV4NT-3Vqj3ooNbruQrK-c6ir_LLoyA71yuPJhkmtT8Ae_mXSDBjuH-TxcXp_htoGbCb_xDgA3zRyRmvc8OSlaHAO-OhtNK_d6x-wiUjM-n0hMdvGNS4oPn1yHyy5WEsg",
    "token_type": "DPoP",
    "expires_in": 3600
}
```

#### 4. Access Token from Refresh Token :

```
curl --location --request POST 'https://localhost:9443/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'dpop: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLTZGNGlydjc2andTaUxIZWJWemtzTGZqdFhZcGxTOVJ3bXZKRmRScC1yYyIsInkiOiJHYlZDRzBDM0xIQjlVbzdDSW9KZUIydk5BaHRlR05EcUh3VmNNRXV5QUkwIn19.eyJodG0iOiJQT1NUIiwic3ViIjoic3ViIiwibmJmIjoxNzE1NjY3NDU5LCJpc3MiOiJpc3N1ZXIiLCJodHUiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJpYXQiOjE3MTU2Njc0NTksImp0aSI6Ijc3NTBjMmQzLTRjNDMtNGY2Ny04MDM1LTEwNWE5YzRmNDgwZCJ9.B-DbYKd95ZKfOrBTHINOwIM-UW0bg8BPY6wWW07M9-jvX_Jm8lKAeCBrp0fDQe7su2vTl0Dcsgxw1OQVJG1eFw' \
--header 'Authorization: Basic NURvT0daQUdBX2xBR2dIMHZaQlJFODNOX2xBYTpaZjl5U3pCUzRPZ3M0eWtuMWJaZmxVZkExTXNh' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=a8dcd0c4-7272-3901-ade2-d24cb8bae241'
```

#### 5. Access Protected Resource :

```
curl --location --request GET 'https://localhost:9443/scim2/Users' \
--header 'accept: application/scim+json' \
--header 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLTZGNGlydjc2andTaUxIZWJWemtzTGZqdFhZcGxTOVJ3bXZKRmRScC1yYyIsInkiOiJHYlZDRzBDM0xIQjlVbzdDSW9KZUIydk5BaHRlR05EcUh3VmNNRXV5QUkwIn19.eyJodG0iOiJHRVQiLCJzdWIiOiJzdWIiLCJuYmYiOjE3MTU2Njc2NjksImF0aCI6IlBsNmYyb3VjZmN0Z0NmS2syWThGeWVwOXBjMmQ1aHNXZmJPQnVtcjZnWHciLCJpc3MiOiJpc3N1ZXIiLCJodHUiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL3NjaW0yXC9Vc2VycyIsImlhdCI6MTcxNTY2NzY2OSwianRpIjoiMmMwYjc3MTUtZWE3Zi00M2U5LWE5ZWUtZGY2YzM0NTBhM2Q1In0.dtrKwkP3qp5DvzOwxWQJFSrKx7Jd3UnIywY2wXqCe1tErPbdECEBxApgVng8vBUUIqTy7jfw3kKeoTUtXLwGpg' \
--header 'Authorization: DPoP 1ce0fc0a-c830-307a-aafc-d25fdc4063ee'
```
&emsp;&ensp;Here, **Authorization Header Value = DPoP {access-token}**

It is important to note that when accessing protected resources, the DPoP proof JWT **MUST** contain the additional 
`ath` claim. Refer [DPoP Proof JWT Syntax](https://datatracker.ietf.org/doc/html/rfc9449#name-dpop-proof-jwt-syntax) for more 
details.

#### 6. Revoke Token :

```
curl --location --request POST 'https://localhost:9443/oauth2/revoke' \
--header 'Content-Type: application/x-www-form-urlencoded;charset=UTF-8' \
--header 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibkNmX3lscldjMTVtejVJZWxSQmJ2TGhLbFV1em4zd1dDSW9ReHVOUThlVSIsInkiOiJhMmU3OTU3S2c3aTVxTUE5UHVpandmSE9nMk95QlRsZ0pVaEhzWGtNaGZnIn19.eyJodG0iOiJQT1NUIiwic3ViIjoic3ViIiwibmJmIjoxNjUyNzY4NjczLCJpc3MiOiJpc3N1ZXIiLCJodHUiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvcmV2b2tlIiwiaWF0IjoxNjUyNzY4NjczLCJqdGkiOiI4OGIzNzBjNS1kYWVmLTQyOWItOTJjNS1iMGFhOTMzOGU1NTQifQ.6qa7IwHY1_xwykRSHRgxABOtBdPkp_nKDKSvCZ_C9GRWZaNtwKJsIwBmlFOYwnzh_yM3HsZj9HaGCBrNZfJ5fQ' \
--header 'Authorization: Basic NURvT0daQUdBX2xBR2dIMHZaQlJFODNOX2xBYTpaZjl5U3pCUzRPZ3M0eWtuMWJaZmxVZkExTXNh' \
--data-urlencode 'token=1ce0fc0a-c830-307a-aafc-d25fdc4063ee' \
--data-urlencode 'token_type_hint=access_token'
```


