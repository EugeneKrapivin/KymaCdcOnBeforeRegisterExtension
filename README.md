# Kyma CDC OnBeforeRegister Extension

a demo of how to do a SAP CD Customer Data Cloud OnBeforeRegisterExtension in kyma

## Resources

* CDC OBR extension <https://help.sap.com/docs/SAP_CUSTOMER_DATA_CLOUD/8b8d6fffe113457094a17701f63e3d6a/f1dd2f1663b0461fbbd83fabd5257d8a.html>
* kyma cdc-extensions <https://github.com/SAP-samples/kyma-runtime-extension-samples/blob/main/cdc-extension/README.md>

## Code

### Source

* Use node 18
* do not be tempted to reformat the code into an `ES module` (the editor will suggest it)
* insert your custom validation logic in the `validatePassword` function
* don't forget to add the [dependencies](#dependencies)

```javascript
const axios = require('axios').default;
const jwt = require('jsonwebtoken');
const getPem = require("rsa-pem-from-mod-exp");

/*
axios.interceptors.request.use(request => {
 console.log('Request:', JSON.stringify(request, null, 2));
 return request
})

// Interceptor to log the response
axios.interceptors.response.use(response => {
 console.log('Response:', response);
 return response
})
*/
async function validatePassword(password) {
 if (password == 'testtest') {
  return {
   success: false,
   errors: ["you are using a bad bad password"]
  };
 }

 return {
  success: true,
  errors: []
 };
}

async function refreshPublicKey(kid) {
 let response = await getJWTPublicKey();
 if (response?.status === 200 && response.data?.statusCode === 200) {
  for (const [key, value] of Object.entries(response.data.keys)) {
   if (kid === value.kid) {
    return {
     n: value.n,
     e: value.e
    };
   }
  }
 }
 return {
  n: null,
  e: null
 };
}

async function getJWTPublicKey() {
 return await axios({
  method: "get",
  url: "https://accounts.us1.gigya.com/accounts.getJWTPublicKey",
  params: {
   V2: "true"
  }
 });
}

async function verifyJWT(sigJwt, n, e) {
 return await jwt.verify(sigJwt, getPem(n, e), {
  algorithms: ["RS256"]
 }, function(err, payload) {
  if (err) {
   console.log("Error validating the JWT. ", err);
   return false;
  } else if (payload) {
   console.log("Validated payload: ", JSON.stringify(payload));
   return true;
  }
 });
}

async function handleExtension(event, context) {
 let responseBody = { status: "OK" };

 if (event?.data?.jws == false) {
  throw new Error('data is empty');
 }

 try {
  let decoded = await jwt.decode(event.data.jws, { complete: true });

  const {n, e} = await refreshPublicKey(decoded.header.kid);
  if (!n && !e) {
   throw new Error('Invalid kid');
  }

  // Validate the JSON Web Token
  const verified = await verifyJWT(event.data.jws, n, e);
  if (!verified) {
   throw new Error('The JWT could not be validated.');
  }

  let extensionPoint = decoded.payload.extensionPoint;
  let data = decoded.payload.data;

  switch (extensionPoint) {
   case 'OnBeforeAccountsRegister':
    let { success, errors } = await validatePassword(data.params.password);

    if (!success) {
      responseBody.status = "FAIL";
      responseBody.data = {
        validationErrors: errors.map(error => ({fieldName: "password", message: error }))
       }
    };
    break;
   default:
    throw new Error('extension point not supported');
  }
 } catch (error) {
  console.error('error:', error);
  responseBody.status = "FAIL";
  responseBody.data = {
   validationErrors: [{
    fieldName: "error",
    message: error
   }]
  };
 } finally {
  return responseBody;
 }
}

module.exports = {
 main: async function(event, context) {
  const response = event.extensions.response;
  
  if (!event?.data?.jws) {
   response.status(400).send({
    status: "FAIL",
    data: {
     validationErrors: [{
      fieldName: "jws",
      message: "empty event body"
     }]
    }
   });
  }
  
  try {
   let result = await handleExtension(event, context);
   console.log("writing result: " + JSON.stringify(result));
   response.status(200).send(result);
  } catch (err) {
   response.status(200).send({
    status: "FAIL",
    errors: [JSON.stringify(err)]
   });
  }
 }
}
```

### Dependencies

```json
{
  "name": "my-cloud-function",
  "version": "1.0.0",
  "description": "My Cloud Function",
  "dependencies": {
    "axios": "^0.24.0",
    "jsonwebtoken": "^8.5.1",
    "rsa-pem-from-mod-exp": "^0.8.5"
  }
}
```
